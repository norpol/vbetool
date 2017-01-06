/*
Run video BIOS code for various purposes

Copyright Matthew Garrett <mjg59@srcf.ucam.org>, heavily based on
vbetest.c from the lrmi package and read-edid.c by John Fremlin

This program is released under the terms of the GNU General Public License,
version 2
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <pciaccess.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/io.h>
#include <sys/kd.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <libx86.h>
#include "vbetool.h"

#define access_ptr_register(reg_frame,reg) (reg_frame -> reg)
#define access_seg_register(reg_frame,es) reg_frame.es
#define real_mode_int(interrupt,reg_frame_ptr) !LRMI_int(interrupt,reg_frame_ptr)

#define DPMS_STATE_ON 0x0000
#define DPMS_STATE_STANDBY 0x0100
#define DPMS_STATE_SUSPEND 0x0200
#define DPMS_STATE_OFF 0x0400
#define DPMS_STATE_LOW 0x0800

static int primary_gpu_has_kernel_driver(void)
{
	struct pci_id_match dev_match = {
	PCI_MATCH_ANY, PCI_MATCH_ANY, PCI_MATCH_ANY, PCI_MATCH_ANY,
	(0x03 << 16), 0xff000, 0 };
	struct pci_device *dev;
	struct pci_device_iterator *iter;
	int ret = 0;

	iter = pci_id_match_iterator_create(&dev_match);
	if (iter == NULL) {
		return 1;
	}

	while ((dev = pci_device_next(iter)) != NULL) {
		int is_boot = pci_device_is_boot_vga(dev);
		if (!is_boot)
			continue;

		if (pci_device_has_kernel_driver(dev)) {
			ret = 1;
			break;
		}
	}
	pci_iterator_destroy(iter);
	return ret;
}

int vbetool_init (void) {
	if (!LRMI_init()) {
		fprintf(stderr, "Failed to initialise LRMI (Linux Real-Mode Interface).\n");
		exit(1);
	}
	
	ioperm(0, 1024, 1);
	iopl(3);
	
	pci_system_init();
	return 0;
}

#ifndef S2RAM
int main(int argc, char *argv[])
{
	/* Don't bother checking for privilege if they only want usage() */
	if (argc < 2)
		goto usage;
	
	vbetool_init();
	
	if (!strcmp(argv[1], "vbestate")) {
		/* VBE save/restore tends to break when done underneath X */
		int err = check_console();

		if (err) {
			return err;
		}

		if (primary_gpu_has_kernel_driver()) {
			fprintf(stderr,"no save or restore with kernel driver loaded\n");
			return 0;
		}
		if (!strcmp(argv[2], "save")) {
			save_state();
		} else if (!strcmp(argv[2], "restore")) {
			restore_state();
		} else {
			goto usage;
		}
	} else if (!strcmp(argv[1], "dpms")) {
		if (!strcmp(argv[2], "on")) {
			return do_blank(DPMS_STATE_ON);
		} else if (!strcmp(argv[2], "suspend")) {
			return do_blank(DPMS_STATE_SUSPEND);
		} else if (!strcmp(argv[2], "standby")) {
			return do_blank(DPMS_STATE_STANDBY);
		} else if (!strcmp(argv[2], "off")) {
			return do_blank(DPMS_STATE_OFF);
		} else if (!strcmp(argv[2], "reduced")) {
			return do_blank(DPMS_STATE_LOW);
		} else {
			goto usage;
		}
	} else if (!strcmp(argv[1], "vbemode")) {

		if (primary_gpu_has_kernel_driver()) {
			fprintf(stderr,"no save or restore with kernel driver loaded\n");
			return 0;
		}

		if (!strcmp(argv[2], "set")) {
			return do_set_mode(atoi(argv[3]),0);
		} else if (!strcmp(argv[2], "get")) {
			return do_get_mode();
		} else {
			goto usage;
		}
	} else if (!strcmp(argv[1], "vgamode")) {

		if (primary_gpu_has_kernel_driver()) {
			fprintf(stderr,"no save or restore with kernel driver loaded\n");
			return 0;
		}

		if (!strcmp(argv[2], "set")) {
			return do_set_mode(atoi(argv[3]),1);
		} else {
			return do_set_mode(atoi(argv[2]),1);
		}
	} else if (!strcmp(argv[1], "post")) {
		/* Again, we don't really want to do this while X is in 
		   control */
		int err = check_console();

		if (err) {
			return err;
		}

		if (argc >= 3) {
			void *rc;
			int romfd = open (argv[2], O_RDWR);

			munmap((void *)0xc0000, 64*1024);
			rc = mmap((void *)0xc0000, 64*1024,
				  PROT_READ|PROT_WRITE|PROT_EXEC,
				  MAP_FIXED|MAP_PRIVATE, romfd, 0);
		}

		return do_post(0);
	} else if (!strcmp(argv[1], "bootpost")) {
		int err = check_console();

		if (err) {
			return err;
		}
		return do_post(1);
	} else if (!strcmp(argv[1], "udevpost")) {
	
#ifdef HAVE_PCI_DEVICE_VGAARB_INIT
		int err = check_console();

		if (err) {
			return err;
		}
		if (argc < 3)
			goto usage;
		
		return do_udev_post(argv[2]);
#else
		fprintf("no vga arb support built in\n");
		return -1;
#endif
	} else if (!strcmp(argv[1], "vgastate")) {

		if (primary_gpu_has_kernel_driver()) {
			fprintf(stderr,"no save or restore with kernel driver loaded\n");
			return 0;
		}

		if (!strcmp(argv[2], "on")) {
			return enable_vga();
		} else {
			return disable_vga();
		}
	} else if (!strcmp(argv[1], "vbefp")) {
		if (!strcmp(argv[2], "id") || !strcmp(argv[2], "panelid")) {
			return do_get_panel_id(0);
		} else if (!strcmp(argv[2], "panelsize")) {
			return do_get_panel_id(1);
		} else if (!strcmp(argv[2], "getbrightness")) {
			return do_get_panel_brightness();
		} else if (!strcmp(argv[2], "setbrightness")) {
			return do_set_panel_brightness(atoi(argv[3]));
		} else if (!strcmp(argv[2], "invert")) {
			return do_invert_panel();
		} else {
			return 1;
		}
	} else {
	      usage:
		fprintf(stderr,
			"%s: Usage %s [[vbestate save|restore]|[vbemode set|get]|[vgamode]|[dpms on|off|standby|suspend|reduced]|[post [romfile]]|[bootpost]|[udevpost pciid]|[vgastate on|off]|[vbefp panelid|panelsize|getbrightness|setbrightness|invert]]\n",
			argv[0], argv[0]);
		return 1;
	}

	return 0;
}
#endif

int do_vbe_service(unsigned int AX, unsigned int BX, reg_frame * regs)
{
	const unsigned interrupt = 0x10;
	unsigned function_sup;
	unsigned success;
	regs->ds = 0x0040;

	access_ptr_register(regs, eax) = AX;
	access_ptr_register(regs, ebx) = BX;

	if (real_mode_int(interrupt, regs)) {
		fprintf(stderr,
			"Error: something went wrong performing real mode interrupt\n");
		return -1;
	}

	AX = access_ptr_register(regs, eax);

	function_sup = ((AX & 0xff) == 0x4f);
	success = ((AX & 0xff00) == 0);

	if (!success) {
		fprintf(stderr, "Real mode call failed\n");
		return -2;
	}

	if (!function_sup) {
		fprintf(stderr, "Function not supported\n");
		return -3;
	}

	return access_ptr_register(regs, ebx);
}

int do_real_post(unsigned pci_device)
{
	int error = 0;
	struct LRMI_regs r;
	memset(&r, 0, sizeof(r));

	/* Several machines seem to want the device that they're POSTing in
	   here */
	r.eax = pci_device;

	/* 0xc000 is the video option ROM.  The init code for each
	   option ROM is at 0x0003 - so jump to c000:0003 and start running */
	r.cs = 0xc000;
	r.ip = 0x0003;

	/* This is all heavily cargo culted but seems to work */
	r.edx = 0x80;
	r.ds = 0x0040;

	if (!LRMI_call(&r)) {
		fprintf(stderr,
			"Error: something went wrong performing real mode call\n");
		error = 1;
	}

	return error;
}

#define MAX_ROMSIZE 64*1024
void *rom_cseg;
unsigned char romfile[MAX_ROMSIZE];

int setup_rom_section(void)
{
  munmap((void *)0xc0000, MAX_ROMSIZE);
  rom_cseg = mmap((void *)0xc0000, MAX_ROMSIZE, PROT_READ|PROT_WRITE|PROT_EXEC,
		  MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
  if (!rom_cseg) {
    fprintf(stderr,"unable to setup fake rom\n");
    return -1;
  }
  return 0;
}

int do_device_post(struct pci_device *dev, int has_arb)
{
	int error = 0;
	/* need to pull the ROM file */
	unsigned int pci_id;
	int ret;	

#ifdef HAVE_PCI_DEVICE_VGAARB_INIT
	if (has_arb) {
		pci_device_vgaarb_set_target(dev);
		pci_device_vgaarb_lock();
		pci_device_enable(dev);
	
		ret = pci_device_read_rom(dev, romfile);
		if (ret) {
			pci_device_vgaarb_unlock();
			fprintf(stderr,"rom read returned %d\n", ret);
			return 0;
		}

		memcpy(rom_cseg, romfile, MAX_ROMSIZE);
	}
#endif
	pci_id = (dev->bus << 8) + (dev->dev << 3) +
		    (dev->func & 0x7);
	error = do_real_post(pci_id);
#ifdef HAVE_PCI_DEVICE_VGAARB_INIT
	if (has_arb)
		pci_device_vgaarb_unlock();
#endif
	return error;
}

/* 0000:01:0a.0 */
int pci_str_to_info(char *pci_string, struct pci_slot_match *match)
{
	int dom, bus, dev, func;
	char *tok;

	tok = strtok(pci_string, ":");
	if (!tok)
		return -1;

	dom = strtoul(tok, NULL, 16);
	tok = strtok(NULL, ":");
	if (!tok)
		return -1;
	bus = strtoul(tok, NULL, 16);
	tok = strtok(NULL, ".");
	if (!tok)
		return -1;
	dev = strtoul(tok, NULL, 16);
	tok = strtok(NULL, ".");
	if (!tok)
		return -1;
	func = strtoul(tok, NULL, 16);
	
	match->domain = dom;
	match->bus = bus;
	match->dev = dev;
	match->func = func;
	return 0;
}

#ifdef HAVE_PCI_DEVICE_VGAARB_INIT
int do_udev_post(char *pci_string)
{
	struct pci_slot_match match;
	int is_boot;
	int error;
	struct pci_device *dev;

	error = pci_device_vgaarb_init();
	if (error)
		return -1;

	if (setup_rom_section())
  		return -1;

	/* parse the PCI string */
	error = pci_str_to_info(pci_string, &match);
	if (error)
		return -1;

	dev = pci_device_find_by_slot(match.domain, match.bus,
			match.dev, match.func);
	if (!dev)
		return -1;
	
	error = pci_device_probe(dev);
	if (error)
		return -1;
	is_boot = pci_device_is_boot_vga(dev);
	if (is_boot)
		return 0;
	if (pci_device_has_kernel_driver(dev))
		return 0;
	error = do_device_post(dev, 1);
	if (error)
		return error;
	pci_device_vgaarb_set_target(NULL);
	pci_device_vgaarb_lock();
	pci_device_vgaarb_unlock();
	pci_device_vgaarb_fini();
	return 0;
}
#endif

int do_post(int boot_flag)
{
	int error;
	struct pci_id_match dev_match = {
	PCI_MATCH_ANY, PCI_MATCH_ANY, PCI_MATCH_ANY, PCI_MATCH_ANY,
	(0x03 << 16), 0xff000, 0 };
	struct pci_device *dev, *first_dev = NULL;
	struct pci_device_iterator *iter;
	int has_arb = 1;
	int ret;

#ifdef HAVE_PCI_DEVICE_VGAARB_INIT
	ret = pci_device_vgaarb_init();
	if (ret)
		has_arb = 0;

	if (has_arb)
		if (setup_rom_section())
	  		return -1;
#else
	if (boot_flag == 1)
		return -1;
	has_arb = 0;
#endif

	iter = pci_id_match_iterator_create(&dev_match);
	if (iter == NULL) {
		return 1;
	}

	while ((dev = pci_device_next(iter)) != NULL) {
		int is_boot = pci_device_is_boot_vga(dev);
		if (!first_dev)
			first_dev = dev;

		if (!is_boot && !has_arb)
			continue;

		if (is_boot && boot_flag) {
			continue;
		}
#ifdef HAVE_PCI_DEVICE_VGAARB_INIT
		if (pci_device_has_kernel_driver(dev)) {
			continue;
		}
#endif
		error = do_device_post(dev, has_arb);
		if (error)
			return error;
	}
	pci_iterator_destroy(iter);
#ifdef HAVE_PCI_DEVICE_VGAARB_INIT
	if (has_arb) {
		pci_device_vgaarb_set_target(first_dev);
		pci_device_vgaarb_lock();
		pci_device_vgaarb_unlock();
		pci_device_vgaarb_fini();
	}
#endif
	return 0;
}

void restore_state_from(char *data)
{
	struct LRMI_regs r;

	/* VGA BIOS mode 3 is text mode */
	do_set_mode(3,1);

	memset(&r, 0, sizeof(r));

	r.eax = 0x4f04;
	r.ecx = 0xf;		/* all states */
	r.edx = 2;		/* restore state */
	r.es = (unsigned int) (data - LRMI_base_addr()) >> 4;
	r.ebx = (unsigned int) (data - LRMI_base_addr()) & 0xf;
	r.ds = 0x0040;

	if (!LRMI_int(0x10, &r)) {
		fprintf(stderr,
			"Can't restore video state (vm86 failure)\n");
	} else if ((r.eax & 0xffff) != 0x4f) {
		fprintf(stderr, "Restore video state failed\n");
	}

	LRMI_free_real(data);

	ioctl(0, KDSETMODE, KD_TEXT);

}

void restore_state(void)
{

	char *data = NULL;
	char tmpbuffer[524288];
	int i, length = 0;

	/* We really, really don't want to fail to read the entire set */
	while ((i = read(0, tmpbuffer + length, sizeof(tmpbuffer)-length))) {
		if (i == -1) {
			if (errno != EAGAIN && errno != EINTR) {
				perror("Failed to read state - ");
				return;
			}
		} else {
			length += i;
		}
	}

	data = LRMI_alloc_real(length);
	memcpy(data, tmpbuffer, length);

	restore_state_from(data);
}

char *__save_state(int *psize)
{
	struct LRMI_regs r;
	char *buffer;
	unsigned int size;

	memset(&r, 0, sizeof(r));

	r.eax = 0x4f04;
	r.ecx = 0xf;		/* all states */
	r.edx = 0;		/* get buffer size */
	r.ds = 0x0040;

	if (!LRMI_int(0x10, &r)) {
		fprintf(stderr,
			"Can't get video state buffer size (vm86 failure)\n");
	}

	if ((r.eax & 0xffff) != 0x4f) {
		fprintf(stderr, "Get video state buffer size failed\n");
	}

	*psize = size = (r.ebx & 0xffff) * 64;

	buffer = LRMI_alloc_real(size);

	if (buffer == NULL) {
		fprintf(stderr, "Can't allocate video state buffer\n");
		return NULL;
	}

	memset(&r, 0, sizeof(r));

	fprintf(stderr, "Allocated buffer at %p (base is 0x%x)\n", buffer,
			LRMI_base_addr());

	r.eax = 0x4f04;
	r.ecx = 0xf;		/* all states */
	r.edx = 1;		/* save state */
	
	r.es = (unsigned int) (buffer - LRMI_base_addr()) >> 4;
	r.ebx = (unsigned int) (buffer - LRMI_base_addr()) & 0xf;
	r.ds = 0x0040;

	fprintf(stderr, "ES: 0x%04X EBX: 0x%04X\n", r.es, r.ebx);

	if (!LRMI_int(0x10, &r)) {
		fprintf(stderr, "Can't save video state (vm86 failure)\n");
	}

	if ((r.eax & 0xffff) != 0x4f) {
		fprintf(stderr, "Save video state failed\n");
	}
	return buffer;
}

void save_state(void)
{
	int size;
	char *buffer = __save_state(&size);
	ssize_t num_written;

	if (buffer)
		/* FIXME: should retry on short write); */
		num_written = write(1, buffer, size);
}

int do_blank(int state)
{
	reg_frame regs;
	int error;

	memset(&regs, 0, sizeof(regs));
	error = do_vbe_service(0x4f10, state |= 0x01, &regs);
	if (error<0) {
		return error;
	}
	return 0;
}

int do_set_mode (int mode, int vga) {
	reg_frame regs;
	int error;

	memset(&regs, 0, sizeof(regs));

	if (vga) {
		error = do_vbe_service(mode, 0, &regs);
	} else {
		error = do_vbe_service(0x4f02, mode, &regs);
	}

	if (error<0) {
		return error;
	}
	
	return 0;
}

int do_get_panel_brightness() {
	reg_frame regs;
	int error;

	memset(&regs, 0, sizeof(regs));

	error = do_vbe_service(0x4f11, 0x05, &regs);

	if (error<0) {
		return error;
	}

	printf("%d\n",regs.ecx);

	return 0;
}

int do_invert_panel() {
	reg_frame regs;
	int error;

	memset(&regs, 0, sizeof(regs));

	error = do_vbe_service(0x4f11, 0x02, &regs);

	if (error<0) {
		return error;
	}

	if ((regs.ebx & 0xff) == 0)
		regs.ecx = 3;
	else
		regs.ecx = 0;

	error = do_vbe_service(0x4f11, 0x0102, &regs);

	if (error<0) {
		return error;
	}

	return 0;
}

int do_set_panel_brightness(int brightness) {
	reg_frame regs;
	int error;

	memset(&regs, 0, sizeof(regs));

	regs.ecx = brightness;

	error = do_vbe_service(0x4f11, 0x0105, &regs);

	if (error<0) {
		return error;
	}

	printf("%d\n",regs.ecx);

	return 0;
}

int do_get_mode() {
	reg_frame regs;
	int error;

	memset(&regs, 0, sizeof(regs));
	error = do_vbe_service(0x4f03, 0, &regs);

	if (error<0) {
		return error;
	}
	
	printf("%d\n",error);
	return 0;
}

int check_console()
{
	struct stat stat;

	return 0;

	if (fstat(0, &stat) != 0) {
		fprintf(stderr, "Can't stat() stdin\n");
		return 10;
	}

	if ((stat.st_rdev & 0xff00) != 0x400 || (stat.st_rdev & 0xff) > 63) {
		fprintf(stderr, "To perform this operation, "
			"this program must be run from the console\n");
		return 11;
	}

	ioctl(0, KDSETMODE, KD_GRAPHICS);
	return 0;
}

int enable_vga() {
	outb(0x03 | inb(0x3CC),  0x3C2);
	outb(0x01 | inb(0x3C3),  0x3C3);
	outb(0x08 | inb(0x46e8), 0x46e8);
	outb(0x01 | inb(0x102),  0x102);
	return 0;
}

int disable_vga() {
	outb(~0x03 & inb(0x3CC),  0x3C2);
	outb(~0x01 & inb(0x3C3),  0x3C3);
	outb(~0x08 & inb(0x46e8), 0x46e8);
	outb(~0x01 & inb(0x102),  0x102);
	return 0;
}

/* Based on xserver-xorg-driver-i810/src/i830_driver.c */
struct panel_id {
  int hsize:16, vsize:16;
  int fptype:16;
  int redbpp:8, greenbpp:8, bluebpp:8, reservedbpp:8;
  int rsvdoffscrnmemsize:32, rsvdoffscrnmemptr:32;
  char reserved[14];
} __attribute__((packed));

int do_get_panel_id(int just_dimensions)
{
  reg_frame r = {
    .eax = 0x4f11,
    .ebx = 0x0001
  };
  struct panel_id *id = LRMI_alloc_real(sizeof(struct panel_id));
  r.es = (unsigned short)(((int)(id-LRMI_base_addr()) >> 4) & 0xffff);
  r.edi = (unsigned long)(id-LRMI_base_addr()) & 0xf;

  if(sizeof(struct panel_id) != 32)
    return fprintf(stderr, "oops: panel_id, sizeof struct panel_id != 32, it's %d...\n", sizeof(struct panel_id)), 7;

  if(real_mode_int(0x10, &r))
    return fprintf(stderr, "Can't get panel id (vm86 failure)\n"), 8;

  if((r.eax & 0xff) != 0x4f)
    return fprintf(stderr, "Panel id function not supported\n"), 9;

  if(r.eax & 0xff00)
    {
      if((r.eax & 0xff00) == 0x100)
	fprintf(stderr, "Panel id read failed\n");
      else
	fprintf(stderr, "Panel id function not successful\n");
      return 10;
    }

  if(!just_dimensions)
    printf("size:\t%d %d\n"
	   "type:\t%d\n"
	   "bpp:\t%d %d %d %d\n",
	   id->hsize, id->vsize,
	   id->fptype,
	   id->redbpp, id->greenbpp, id->bluebpp, id->reservedbpp);
  else
    printf("%dx%d\n", id->hsize, id->vsize);

#if 0

  /* Don't have a use for these and they don't seem to be documented.
   * 320 appears to be 320kB of mapped memory and the following
   * pointer is 0x1ffb8000 which is kernel mapping + 0xb8000 offset.
   */
  printf("ram:\t%dkB\n"
	 "offset:\t%p\n",
	 id->rsvdoffscrnmemsize,
	 (void *)id->rsvdoffscrnmemptr);
#endif

  return 0;
}
