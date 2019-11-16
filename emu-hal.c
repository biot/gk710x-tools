#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <endian.h>

#include <unicorn/unicorn.h>


#define DEBUG 0
#define WEDGE 0


// memory address where emulation starts
#define MEMORY		0xc0000000
#define MEM_SIZE	0x00200000
#define STACK		0xc0000000
#define STACK_SIZE	0x00008000

#define HAL_START	0xc0012000
#define INIT_WEDGE_ADDR	0xc0016000
#define HW_OPS_ENTRIES	18
#define WEDGE_LOG	0xc0017000
#define WEDGE_LOG_SIZE	0x9000

#if 0
#define HAL_INIT_ARG0	0xf0000000
#define HAL_INIT_ARG1	0xf1000000
#define HAL_INIT_ARG2	0xf2000000
#define HAL_INIT_ARG3	0xf3000000
#else
#define HAL_INIT_ARG0	0x0
#define HAL_INIT_ARG1	0x0
#define HAL_INIT_ARG2	0x90000000
#define HAL_INIT_ARG3	0xa0000000
#endif
#define HAL_INIT_ARG4	0x0


bool got_new_address = 0;
uint32_t new_address;

struct {
	char *filename;
	uint32_t addr_hw_readl;
} halcode[] = {
//	{ "halcode-fromsrc", 0xc00128cc },
	{ "halcode-fromdevice", 0xc00127e8 },
	{ NULL }
};

uint8_t code[] = {
	0x04, 0x40, 0x9f, 0xe5,	// ldr r4, [pc #8]
	0x04, 0x00, 0x9f, 0xe5,	// ldr r0, [pc #8]
	0x34, 0xff, 0x2f, 0xe1,	// blx r4
	0x00, 0x00, 0x00, 0x00,	// pointer to hw_readl()
	0x00, 0x00, 0x00, 0x00,	// test address goes here
};

static void dumpregs(uc_engine *uc)
{
#if DEBUG		
	uint32_t r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, pc;

	uc_reg_read(uc, UC_ARM_REG_PC, &pc);
	uc_reg_read(uc, UC_ARM_REG_R0, &r0);
	uc_reg_read(uc, UC_ARM_REG_R1, &r1);
	uc_reg_read(uc, UC_ARM_REG_R2, &r2);
	uc_reg_read(uc, UC_ARM_REG_R3, &r3);
	uc_reg_read(uc, UC_ARM_REG_R4, &r4);
	uc_reg_read(uc, UC_ARM_REG_R5, &r5);
	uc_reg_read(uc, UC_ARM_REG_R6, &r6);
	uc_reg_read(uc, UC_ARM_REG_R7, &r7);
	uc_reg_read(uc, UC_ARM_REG_R8, &r8);
	uc_reg_read(uc, UC_ARM_REG_R9, &r9);
	uc_reg_read(uc, UC_ARM_REG_R10, &r10);
	printf("  R0 = 0x%.8x	R6 = 0x%.8x\n", r0, r6);
	printf("  R1 = 0x%.8x	R7 = 0x%.8x\n", r1, r7);
	printf("  R2 = 0x%.8x	R8 = 0x%.8x\n", r2, r8);
	printf("  R3 = 0x%.8x	R9 = 0x%.8x\n", r3, r9);
	printf("  R4 = 0x%.8x	R10= 0x%.8x\n", r4, r10);
	printf("  R5 = 0x%.8x	PC = 0x%.8x\n", r5, pc);
#endif
}

#if DEBUG
static uint32_t get_pc(uc_engine *uc)
{
	uint32_t pc;

	uc_reg_read(uc, UC_ARM_REG_PC, &pc);

	return pc;
}
#endif

static void hook_mem(uc_engine *uc, uc_mem_type type, uint64_t address,
		     int size, int64_t value, void *user_data)
{
#if DEBUG
	printf("hook_mem: PC 0x%x", get_pc(uc));
	printf(" address 0x%"PRIx64, address);
	printf(" size 0x%x", size);
	printf(" type %d value 0x%x\n", type, (unsigned int)value);
#endif
}

static bool hook_mem_invalid(uc_engine *uc, uc_mem_type type, uint64_t address,
		     int size, int64_t value, void *user_data)
{
#if DEBUG
	printf("hook_mem_invalid: PC 0x%x", get_pc(uc));
	printf(" address 0x%"PRIx64, address);
	printf(" size 0x%x", size);
	printf(" type %d value 0x%x\n", type, (unsigned int)value);

	dumpregs(uc);
#endif

	got_new_address = 1;
	new_address = address;

	return 1;
}

int read_file(char *filename, uint8_t **buf)
{
	FILE *f;
	struct stat st;

	if (stat(filename, &st) < 0) {
		printf("unable to open %s: %s\n", filename, strerror(errno));
		exit(errno);
	}

	*buf = malloc(st.st_size);
	f = fopen(filename, "r");
	if (!f) {
		printf("unable to open %s: %s\n", filename, strerror(errno));
		exit(errno);
	}
	fread(*buf, st.st_size, 1, f);
	fclose(f);

	return st.st_size;
}

static void savemem(uc_engine *uc, char *filename, uint32_t start, int size)
{
	FILE *f;
	uint8_t *buf;
	uc_err err;

	f = fopen(filename, "w");
	buf = malloc(size);

	if ((err = uc_mem_read(uc, start, buf, size)) != UC_ERR_OK) {
		printf("Failed to write %s: %d\n", filename, err);
		exit(-1);
	}
	fwrite(buf, size, 1, f);
	fclose(f);
	free(buf);
}

static void run_arm(char *halcodefile)
{
	uc_engine *uc;
	uc_err err;
	uc_hook hh;
	uint32_t sp = STACK + STACK_SIZE;	 // top of stack
	uint32_t r0, r1, r2, r3, r4;
	uint32_t g_hw, hw_readl;
	uint8_t *buf, *buf2;
	int buf_size, wedge_size;

	// Initialize emulator in ARM mode
	err = uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);
	if (err != UC_ERR_OK) {
		printf("Failed on uc_open() with error returned: %u (%s)\n",
				err, uc_strerror(err));
		exit(-1);
	}

	// map main memory
	if ((err = uc_mem_map(uc, MEMORY, MEM_SIZE, UC_PROT_ALL)) != UC_ERR_OK) {
		printf("memory map failed: %d\n", err);
		exit(-1);
	}

	// set stack pointer
	sp = STACK + STACK_SIZE;
	uc_reg_write(uc, UC_ARM_REG_SP, &sp);

	// fill stack with markers
	buf2 = malloc(STACK_SIZE + WEDGE_LOG_SIZE);
	memset(buf2, 0xaa, STACK_SIZE + WEDGE_LOG_SIZE);
	uc_mem_write(uc, STACK, buf2, STACK_SIZE);

	// write hal invocation code
	if ((err = uc_mem_write(uc, MEMORY, code, sizeof(code))) != UC_ERR_OK) {
		printf("init write failed: %d\n", err);
		exit(-1);
	}

	// write hal code
	buf_size = read_file(halcodefile, &buf);
	if ((err = uc_mem_write(uc, HAL_START, buf, buf_size)) != UC_ERR_OK) {
		printf("mem write failed: %d\n", err);
		exit(-1);
	}
	free(buf);

	uc_hook_add(uc, &hh, UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem, NULL, MEMORY,
		MEM_SIZE);
	uc_hook_add(uc, &hh, UC_HOOK_MEM_UNMAPPED, hook_mem_invalid, NULL, MEMORY,
		MEM_SIZE);

	if (WEDGE) {
		// write wedge code
		wedge_size = read_file("hal-init-wedge", &buf);
		if ((err = uc_mem_write(uc, INIT_WEDGE_ADDR, buf, wedge_size)) != UC_ERR_OK) {
			printf("wedge write failed: %d\n", err);
			exit(-1);
		}
		free(buf);

		// fill wedgelog with markers
		uc_mem_write(uc, WEDGE_LOG, buf2, WEDGE_LOG_SIZE);
		free(buf2);

		// call install_init_wedge
		if (DEBUG)
			printf("install_init_wedge() at 0x%x\n", INIT_WEDGE_ADDR);
		r3 = 0x33333333;
		r4 = 0x44444444;
		uc_reg_write(uc, UC_ARM_REG_R3, &r3);
		uc_reg_write(uc, UC_ARM_REG_R4, &r4);
		err = uc_emu_start(uc, INIT_WEDGE_ADDR, INIT_WEDGE_ADDR + 0x14, 0, 0);
		if (err != UC_ERR_OK) {
			printf("Failed on install_init_wedge() with error returned: %u\n", err);
			exit(-1);
		}
	}

	// initialize 5 arguments to hal_init()
	r0 = HAL_INIT_ARG0;
	r1 = HAL_INIT_ARG1;
	r2 = HAL_INIT_ARG2;
	r3 = HAL_INIT_ARG3;
	r4 = HAL_INIT_ARG4;
	sp -= 4;
	uc_mem_write(uc, sp, &r4, 4);

	uc_reg_write(uc, UC_ARM_REG_R0, &r0);
	uc_reg_write(uc, UC_ARM_REG_R1, &r1);
	uc_reg_write(uc, UC_ARM_REG_R2, &r2);
	uc_reg_write(uc, UC_ARM_REG_R3, &r3);
	uc_reg_write(uc, UC_ARM_REG_SP, &sp);

	// call hal_init()
	if (DEBUG)
		printf("hal_init() at 0x%x\n", HAL_START);

	if (WEDGE) {
		// stop before post_init_wedge() -- hal_init() patch is call-terminated
		err = uc_emu_start(uc, HAL_START, INIT_WEDGE_ADDR + 0x4c, 0, 0);
	} else {
		err = uc_emu_start(uc, HAL_START, HAL_START + 0x13c, 0, 0);
	}
	if (err != UC_ERR_OK) {
		printf("Failed on hal_init() with error returned: %u\n", err);
		dumpregs(uc);
		exit(-1);
	}
	uc_reg_read(uc, UC_ARM_REG_R0, &r0);
	g_hw = le32toh(r0);
	if (DEBUG)
		printf("g_hw is at 0x%x\n", g_hw);

	// find hw_readl pointer in g_hw
	uc_mem_read(uc, g_hw + 4 * 4, &hw_readl, 4);
	if (DEBUG)
		printf("hw_readl is at 0x%x\n", hw_readl);
	if ((err = uc_mem_write(uc, MEMORY + 0x0c, &hw_readl, 4)) != UC_ERR_OK) {
		printf("hw_readl write failed: %d\n", err);
		exit(-1);
	}

	// call hw_readl()
	if (DEBUG)
		printf("calling hw_readl()\n");
	err = uc_emu_start(uc, MEMORY, MEMORY + 0x0c, 0, 0);
	if (err != UC_ERR_OK && !got_new_address) {
		printf("Failed on hw_readl() with error returned: %u\n", err);
		exit(-1);
	}

#if DEBUG
	if (WEDGE)
		savemem(uc, "mem-wedgecode", INIT_WEDGE_ADDR, wedge_size);
	savemem(uc, "mem-halinit", HAL_START, 0x1000);
	savemem(uc, "mem-hw_ops", g_hw, 4 * HW_OPS_ENTRIES);
#endif
	savemem(uc, "mem-wedgelog", WEDGE_LOG, WEDGE_LOG_SIZE);

	if (DEBUG)
		printf("finished.\n");
	dumpregs(uc);

	uc_close(uc);
}

int main(int argc, char **argv, char **envp)
{
	uint32_t testaddress;
	int found, i;
	char *s;

	if (argc != 3 || strlen(argv[2]) != 10 || strncasecmp(argv[2], "0x", 2)) {
		printf("Usage: emu-hal <halcode file> <hex address>\n");
		exit(EINVAL);
	}

	found = 0;
	for (i = 0; halcode[i].filename; i++) {
		if (strlen(argv[1]) < strlen(halcode[i].filename))
			continue;
		s = argv[1] + strlen(argv[1]) - strlen(halcode[i].filename);
		if (!strcmp(s, halcode[i].filename)) {
			found = 1;
			break;
		}
	}
	if (!found) {
		printf("Unknown HAL code '%s'\n", argv[1]);
		exit(errno);
	}

	errno = 0;
	testaddress = strtol(argv[2] + 2, NULL, 16);
	if (errno) {
		printf("invalid address %s\n", argv[2]);
		exit(errno);
	}

	*(uint32_t *)(code + 0x10) = htole32(testaddress);


	run_arm(argv[1]);
	if (got_new_address)
		printf("0x%.8x -> 0x%.8x\n", testaddress, new_address);

	return 0;
}
