#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>

#define OPERAND_NONE		 0x00
#define OPERAND_REGISTER	 0x01
#define OPERAND_REGISTER_OFFSET  0x02
#define OPERAND_BYTE_ADDRESS	 0x04
#define OPERAND_RELATIVE_ADDRESS 0x08
#define OPERAND_BRANCH_ADDRESS	 0x10
#define OPERAND_IO_REGISTER	 0x20
#define OPERAND_DATA		 0x40
#define OPERAND_BIT		 0x80

struct Instruction {
	char mnemonic[5];
	int  operands;
	uint32_t operand_mask[2];
	int operand_type[2];
	uint32_t instruction_mask;
};

struct OperandFormat {
	int operand_type;
	char format[6];
};

struct OperandFormat OP_FORMAT[8] = {

	{OPERAND_BRANCH_ADDRESS,   ".%+d"  },
	{OPERAND_BIT,		   "%d"    },
	{OPERAND_RELATIVE_ADDRESS, ".%+d"  },
	{OPERAND_BYTE_ADDRESS,     "0x%02X"},
	{OPERAND_REGISTER,	   "r%d"   },
	{OPERAND_REGISTER_OFFSET,  "r%d"   },
	{OPERAND_IO_REGISTER,	   "0x%02X"},
	{OPERAND_DATA,		   "0x%02X"},

};

struct Instruction AVR_INSTRUCTION_SET[14] = {

	{"jmp",  1, {0x1f1ffff, 0x0000}, {OPERAND_BYTE_ADDRESS, OPERAND_NONE}, 0x940c0000},
	{"call", 1, {0x1f1ffff, 0x0000}, {OPERAND_BYTE_ADDRESS, OPERAND_NONE}, 0x940e0000},

	{"cli",  0, {0x0000, 0x0000}, {OPERAND_NONE, OPERAND_NONE}, 0x94f8},
	{"nop",  0, {0x0000, 0x0000}, {OPERAND_NONE, OPERAND_NONE}, 0x0000},

	{"rjmp", 1, {0x0fff, 0x0000},  {OPERAND_RELATIVE_ADDRESS, OPERAND_NONE}, 0xc000},
	{"cbi",  2, {0x00f8, 0x0007},  {OPERAND_IO_REGISTER, OPERAND_BIT},       0x9800},
	{"subi", 2, {0x00f0, 0x0f0f},  {OPERAND_REGISTER_OFFSET, OPERAND_DATA},  0x5000},
	{"breq", 1, {0x03f8, 0x0000},  {OPERAND_BRANCH_ADDRESS, OPERAND_NONE},   0xf001},
	{"brne", 1, {0x03f8, 0x0000},  {OPERAND_BRANCH_ADDRESS, OPERAND_NONE},   0xf401},
	{"out",  2, {0x060f, 0x01f0},  {OPERAND_IO_REGISTER, OPERAND_REGISTER},  0xb800},
	{"ldi",  2, {0x00f0, 0x0f0f},  {OPERAND_REGISTER_OFFSET, OPERAND_DATA},  0xe000},
	{"eor",  2, {0x01f0, 0x020f},  {OPERAND_REGISTER, OPERAND_REGISTER},     0x2400},
	{"sbi",  2, {0x00f8, 0x0007},  {OPERAND_IO_REGISTER, OPERAND_BIT},       0x9a00},
	{"sbci", 2, {0x00f0, 0x0f0f},  {OPERAND_REGISTER_OFFSET, OPERAND_DATA},  0x4000},
};

unsigned long int hex_to_int(char *nptr) {

	char *endptr = NULL;
	errno = 0;

	unsigned long int i = strtoul(nptr, &endptr, 16);
	if (nptr == endptr || (i == 0 && errno != 0)) {
		fprintf(stderr, "ihex2avr: bad input %s\n", nptr);
		errno = EINVAL;
	}

	return i;
}

int disasm_operand(int operand, int operand_type) {

	int operand_disasm = operand;
	switch (operand_type) {

		case OPERAND_BYTE_ADDRESS:
			operand_disasm <<= 1;
			break;
		case OPERAND_REGISTER_OFFSET:
			operand_disasm += 16;
			break;
		case OPERAND_BRANCH_ADDRESS:
			operand_disasm = (operand_disasm & (1 << 6)) ? ((-1 << 7) | (operand_disasm & 0x7f)) : operand_disasm & 0x7f;
			operand_disasm <<= 1;
			break;
		case OPERAND_RELATIVE_ADDRESS:
			operand_disasm = (operand_disasm & (1 << 11)) ? ((-1 << 12) | (operand_disasm & 0xfff)) : operand_disasm & 0xfff;
			operand_disasm <<= 1;
			break;
	}

	return operand_disasm;
} 

int operand_bits_from_opcode(uint32_t opcode, uint32_t mask, int length) {

	int shift = 0;
	int bits  = 0;

	for (int i = 0; i < length * 8; i++) {

		if ((mask >> i) & 1) {
			if ((opcode >> i) & 1) {
				bits |= (1 << shift);
			}
			shift++;
		}
	}
	return bits;
}

void print_instruction(size_t *addr, uint32_t opcode, int length, struct Instruction instr) {

	int operand;
	int operand_type;

	printf("%02zx:    ", *addr);
	if (length == 4) {
		printf("%02x %02x %02x %02x    ", 
			opcode >> 24, (opcode >> 16) & 0xff, (opcode >> 8) & 0xff, opcode & 0xff
		);
	} else {
		printf("%02x %02x    ", (opcode >> 8) & 0xff, opcode & 0xff);
	}

	if (length == 2) {
		fputs("      ", stdout);
	}

	fputs(instr.mnemonic, stdout);
	fputs(strlen(instr.mnemonic) == 4 ? "   " : "    ", stdout);

	for (int i = 0; i < instr.operands; i++) {

		operand_type = instr.operand_type[i];
		operand      = disasm_operand(operand_bits_from_opcode(opcode, instr.operand_mask[i], length), operand_type);

		for (int k = 0; i < sizeof(OP_FORMAT) / sizeof(OP_FORMAT[0]); k++) {
			if (OP_FORMAT[k].operand_type == operand_type) {
				printf(OP_FORMAT[k].format, operand);
				fputs(" ", stdout);
				break;
			}
		}
	}
	fputs("\n", stdout);
}

void fail(FILE *fp, char *char_buff, uint8_t *uint_buff) {
	free(char_buff);
	free(uint_buff);
	fclose(fp);
	exit(EXIT_FAILURE);
}

void parse_ihex_str(size_t *offset, uint16_t len, uint8_t checksum, uint8_t type, uint16_t addr, char *char_buff, uint8_t *uint_buff, FILE *fp) {
	uint8_t msb, lsb, sum = 0;
	char lsb_buff[3];
	char msb_buff[3];

	for (int i = 0; i < len; i += 4) {

		memcpy(msb_buff, char_buff + i, 2);
		memcpy(lsb_buff, char_buff + i + 2, 2);

		msb = hex_to_int(msb_buff); if (errno != 0) fail(fp, char_buff, uint_buff);
		lsb = hex_to_int(lsb_buff); if (errno != 0) fail(fp, char_buff, uint_buff);

		sum = sum + msb + lsb;

		//printf("%02X%02X ", lsb, msb);
		uint_buff[i / 2]       = lsb; 
		uint_buff[(i / 2) + 1] = msb;
	}

	//fputs("\n\n", stdout);
	sum = sum + type + (len / 2) + (addr >> 8) + (addr & 0xff);
	if (((~sum + 1) & 0xff) != checksum) {
		fprintf(stderr, "ihex2avr: checksum mismatch\n");
		fail(fp, char_buff, uint_buff);
	}

	for (int i = 0; i < len / 2; i++) {

		uint32_t opcode = uint_buff[i] << 8 | uint_buff[i + 1];
		int length = (opcode >> 9) == 0x4a ? 4 : 2;

		if (length == 4) {
			opcode = uint_buff[i + 3] << 0  | 
				 uint_buff[i + 2] << 8  | 
				 uint_buff[i + 1] << 16 | 
				 uint_buff[i + 0] << 24;
		}

		struct Instruction instruction;
		for (int j = 0; j < sizeof(AVR_INSTRUCTION_SET) / sizeof(struct Instruction); j++) {

			uint32_t bits = opcode;
			instruction = AVR_INSTRUCTION_SET[j];

			for (int k = 0; k < instruction.operands; k++) {
				bits &= ~instruction.operand_mask[k];
			}

			if (bits == instruction.instruction_mask) {
				print_instruction(offset, opcode, length, instruction);
				break;
			}
		}

		i += length - 1;
		(*offset) += length;
	}
	//fputs("\n", stdout);
}

void parse_ihex(char *argv[]) {

	FILE* file = fopen(argv[1], "r");
	if (file == NULL) {
		fprintf(stderr, "ihex2avr: could not open %s\n", argv[1]);
		exit(EXIT_FAILURE);
	}

	uint8_t  type, checksum;
	uint16_t length, address;

	size_t buff_size = 0;
	size_t offset    = 0;

	char flen_buff[3];
	char addr_buff[5];
	char type_buff[3];
	char chks_buff[3];

	char *char_buff	   = NULL;
	char *temp_buff	   = NULL;
	uint8_t *uint_buff = NULL;

	while (!feof(file)) {

		char ch = fgetc(file);
		if (ch != ':') {
			break;
		}
		
		if (fgets(flen_buff, 3, file) == NULL) { fprintf(stderr, "ihex2avr: unexpected EOF\n"); fail(file, char_buff, uint_buff); }
		if (fgets(addr_buff, 5, file) == NULL) { fprintf(stderr, "ihex2avr: unexpected EOF\n"); fail(file, char_buff, uint_buff); }
		if (fgets(type_buff, 3, file) == NULL) { fprintf(stderr, "ihex2avr: unexpected EOF\n"); fail(file, char_buff, uint_buff); }

		length  = hex_to_int(flen_buff); if (errno != 0) fail(file, char_buff, uint_buff);
		address = hex_to_int(addr_buff); if (errno != 0) fail(file, char_buff, uint_buff);
		type	= hex_to_int(type_buff); if (errno != 0) fail(file, char_buff, uint_buff);

		if (length == 0) {
			continue;
		}

		if (buff_size == 0) {
			char_buff = (char *)    malloc(length * 2 + 1);
			uint_buff = (uint8_t *) malloc(length);
		} else {

			temp_buff = realloc(char_buff, length * 2 + 1);
			if (temp_buff == NULL) {
				fprintf(stderr, "ihex2avr: Failed to reallocate memory for DATA field, %d\n", length * 2 + 1);
				fail(file, char_buff, uint_buff);
			}

			char_buff = temp_buff;
			temp_buff = realloc(uint_buff, length);

			if (temp_buff == NULL) {
				fprintf(stderr, "ihex2avr: memory allocation failed %d\n", length);
				fail(file, char_buff, uint_buff);
			}

			uint_buff = (uint8_t *) temp_buff;
		}

		length	  = length * 2 + 1;
		buff_size = length;

		if (char_buff == NULL) {
			fprintf(stderr, "ihex2avr: failed to allocate memory for DATA field\n");
			fail(file, char_buff, uint_buff);
		}
		if (fgets(char_buff, length, file) == NULL) {
			fprintf(stderr, "ihex2avr: failed to read DATA field\n");
			fail(file, char_buff, uint_buff);
		}
		if (fgets(chks_buff, 3, file) == NULL) { 
			fprintf(stderr, "ihex2avr: failed to read CHECKSUM field\n"); 
			fail(file, char_buff, uint_buff);
		}

		//printf("Length: %d ",  (int) length - 1);
		//printf("Address: %d ", (int) address);
		//printf("Type: %d ",    (int) type);

		checksum = hex_to_int(chks_buff); if (errno != 0) fail(file, char_buff, uint_buff);		
		parse_ihex_str(&offset, length - 1, checksum, type, address, char_buff, uint_buff, file);
		fgetc(file);	
	}

	free(char_buff);
	free(uint_buff);
	fclose(file);
}

int main(int argc, char *argv[]) {

	if (argc != 2) {
		fprintf(stderr, "Usage: ihex2avr <file_path>\n");
		return EXIT_FAILURE;
	}

	parse_ihex(argv);
	return EXIT_SUCCESS;
}

