/* radare - LGPL3 - 2016 - edsrzf */

#include <r_bin.h>

typedef enum {
	SNES_INVALID,
	SNES_LOROM,
	SNES_HIROM,
	SNES_EXLOROM,
	SNES_EXHIROM
} snes_mapper;

typedef struct {
	bool rom_header; // does the ROM have a 200-byte header?
	snes_mapper mapper;
	ut16 reset; // reset vector
} snes_obj;

enum {
	INTERNAL_HEADER_SIZE = 0x40,

	CHECKSUM_OFFSET = 0x1c,
	RESET_OFFSET = 0x3c,
};

static int check_header(const ut8 *buf, ut64 length, ut64 addr) {
	if (length <= addr + INTERNAL_HEADER_SIZE) {
		return 0;
	}
	buf += addr;

	// We don't require a valid checksum, but we do require that the
	// checksum and checksum complement at least agree with each other.
	ut16 cchecksum = ut8p_bw (buf + CHECKSUM_OFFSET);
	ut16 checksum = ut8p_bw (buf + CHECKSUM_OFFSET + 2);
	if (checksum + cchecksum != 0xffff) {
		return 0;
	}

	ut16 reset = ut8p_bw (buf + RESET_OFFSET);
	if (reset < 0x8000) {
		return 0;
	}

	return 1;
}

#define ROM_HEADER_SIZE 512

static int find_header(const ut8 *buf, ut64 length, snes_obj *obj) {
	// An SNES ROM may or may not have a 512-byte copier header.
	// There are at least three different formats, all the same size,
	// but their contents differ and are unreliable.
	// If we think we have a header, we ignore it.
	switch (length % 0x8000) {
	case 0: // no header
		break;
	case ROM_HEADER_SIZE: // header; ignore it
		if (obj)
			obj->rom_header = true;
		buf += ROM_HEADER_SIZE;
		length -= ROM_HEADER_SIZE;
		break;
	default: // strange file size; not SNES
		return 0;
	}

	// There's also an internal SNES header that all games have.
	// However, there are three possible locations for the header.
	// We have to check them all and look for the most likely suspect.
	snes_mapper mapper = SNES_INVALID;
	ut64 header_offset = 0;
	if (check_header (buf, length, 0x40ffc0)) {
		header_offset = 0x40ffc0;
		mapper = SNES_EXHIROM;
	} else if (check_header (buf, length, 0x00ffc0)) {
		header_offset = 0x00ffc0;
		mapper = SNES_HIROM;
	} else if (check_header (buf, length, 0x007fc0)) {
		header_offset = 0x007fc0;
		if (length >= 0x401000)
			mapper = SNES_EXLOROM;
		else
			mapper = SNES_LOROM;
	}
	if (obj) {
		obj->mapper = mapper;
		obj->reset = ut8p_bw (buf + header_offset + RESET_OFFSET);
	}
	return mapper != SNES_INVALID;
}

static int check_bytes(const ut8 *buf, ut64 length) {
	return find_header (buf, length, NULL);
}

static void *load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	snes_obj *obj = R_NEW0 (snes_obj);
	find_header (buf, sz, obj);
	return obj;
}

static int destroy(RBinFile *arch) {
	free (arch->o->bin_obj);
	return 1;
}

static RList* entries(RBinFile *arch) {
	snes_obj *obj = arch->o->bin_obj;
	RList *ret = r_list_new ();
	RBinAddr *addr = R_NEW0 (RBinAddr);

	switch (obj->mapper) {
	case SNES_LOROM:
	case SNES_EXLOROM:
		addr->paddr = obj->reset - 0x8000;
		break;
	case SNES_HIROM:
		addr->paddr = obj->reset;
		break;
	case SNES_EXHIROM:
		addr->paddr = obj->reset - 0x400000;
		break;
	case SNES_INVALID:
		return NULL;
	}
	if (obj->rom_header)
		addr->paddr += ROM_HEADER_SIZE;
	addr->vaddr = obj->reset;
	r_list_append (ret, addr);
	return ret;
}

static void lorom_sections(RList *ret, int header_size) {
	RBinSection *section = NULL;
	int i;
	for (i = 0; i < 0x80; i++) {
		RBinSection *mirror = NULL;
		section = R_NEW0 (RBinSection);
		snprintf (section->name, R_BIN_SIZEOF_STRINGS, "BANK_%02X_ROM", i);
		section->paddr = header_size + 0x008000*i;
		section->size = 0x008000;
		section->vaddr = 0x010000*i + 0x008000;
		section->vsize = 0x008000;
		section->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_EXECUTABLE | R_BIN_SCN_MAP;
		section->add = true;
		r_list_append (ret, section);

		mirror = R_NEW (RBinSection);
		memcpy (mirror, section, sizeof (RBinSection));
		snprintf (mirror->name, R_BIN_SIZEOF_STRINGS, "BANK_%02X_ROM", i + 0x80);
		mirror->vaddr = 0x010000*i + 0x808000;
		r_list_append (ret, mirror);
	}

	for (i = 0xfe; i < 0x100; i++) {
		section = R_NEW0 (RBinSection);
		snprintf (section->name, R_BIN_SIZEOF_STRINGS, "BANK_%02X_ROM", i);
		section->paddr = header_size + 0x008000*i - 0x400000;
		section->size = 0x008000;
		section->vaddr = 0x010000*i + 0x008000;
		section->vsize = 0x008000;
		section->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_EXECUTABLE | R_BIN_SCN_MAP;
		r_list_append (ret, section);
	}
}

static void hirom_sections(RList *ret, int header_size) {
	RBinSection *section = NULL;
	int i;
	for (i = 0; i < 0x40; i++) {
		RBinSection *mirror = NULL;
		section = R_NEW0 (RBinSection);
		snprintf (section->name, R_BIN_SIZEOF_STRINGS, "BANK_%02X_ROM", i);
		section->paddr = header_size + 0x010000*i + 0x008000;
		section->size = 0x008000;
		section->vaddr = 0x010000*i + 0x008000;
		section->vsize = 0x008000;
		section->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_EXECUTABLE | R_BIN_SCN_MAP;
		section->add = true;
		r_list_append (ret, section);

		mirror = R_NEW (RBinSection);
		memcpy (mirror, section, sizeof (RBinSection));
		snprintf (mirror->name, R_BIN_SIZEOF_STRINGS, "BANK_%02X_ROM", i + 0x80);
		mirror->vaddr = 0x010000*i + 0x808000;
		r_list_append (ret, mirror);
	}

	section = R_NEW0 (RBinSection);
	strncpy (section->name, "BANKS_40_7D_ROM", R_BIN_SIZEOF_STRINGS);
	section->paddr = header_size;
	section->size = 0x3d000;
	section->vaddr = 0x400000;
	section->vsize = 0x3d0000;
	section->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_EXECUTABLE | R_BIN_SCN_MAP;
	section->add = true;
	r_list_append (ret, section);

	section = R_NEW0 (RBinSection);
	strncpy (section->name, "BANKS_C0_FF_ROM", R_BIN_SIZEOF_STRINGS);
	section->paddr = header_size;
	section->size = 0x40000;
	section->vaddr = 0xc00000;
	section->vsize = 0x400000;
	section->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_EXECUTABLE | R_BIN_SCN_MAP;
	section->add = true;
	r_list_append (ret, section);
}

static RList* sections(RBinFile *arch) {
	snes_obj *obj = arch->o->bin_obj;
	int header_size = obj->rom_header ? ROM_HEADER_SIZE : 0;
	RList *ret = r_list_new ();
	switch (obj->mapper) {
	case SNES_LOROM:
		eprintf("lorom; header: %d\n", header_size);
		lorom_sections (ret, header_size);
		break;
	case SNES_HIROM:
		eprintf("hirom; header: %d\n", header_size);
		hirom_sections (ret, header_size);
		break;
	default:
		// XXX: implement ExLoROM, ExHiROM
		break;
	}
	
	return ret;
}

static RBinInfo *info(RBinFile *arch) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret)
		return NULL;
	ret->file = strdup (arch->file);
	ret->type = strdup ("ROM");
	ret->machine = strdup ("SNES");
	ret->os = strdup ("snes");
	ret->arch = strdup ("snes");
	ret->bits = 16;
	ret->has_va = 1;
	ret->dbg_info = R_BIN_DBG_STRIPPED;
	return ret;
}

static RList *mem(RBinFile *arch) {
	RBinMem *m, *n;
	RList *ret = r_list_new ();
	ret->free = free;

	m = R_NEW0 (RBinMem);
	m->name = strdup ("WRAM");
	m->addr = 0x7e0000;
	m->size = 0x7fffff - 0x7e0000;
	m->perms = r_str_rwx ("rwx");
	m->mirrors = r_list_new ();
	r_list_append(ret, m);

	n = R_NEW0 (RBinMem);
	n->name = strdup ("Low WRAM mirror 1");
	n->addr = 0x000000;
	n->size = 0x001fff;
	n->perms = r_str_rwx ("rwx");
	r_list_append(m->mirrors, n);

	n = R_NEW0 (RBinMem);
	n->name = strdup ("Low WRAM mirror 2");
	n->addr = 0x800000;
	n->size = 0x001fff;
	n->perms = r_str_rwx ("rwx");
	r_list_append(m->mirrors, n);

	return ret;
}

static RList *strings(RBinFile *arch) {
	return NULL;
}

struct r_bin_plugin_t r_bin_plugin_snes = {
	.name = "snes",
	.desc = "SNES",
	.license = "LGPL3",
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check_bytes = &check_bytes,
	.entries = &entries,
	.sections = &sections,
	.info = &info,
	.mem = &mem,
	.strings = &strings,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_snes,
	.version = R2_VERSION
};
#endif
