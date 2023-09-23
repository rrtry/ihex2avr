#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

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
	int offset;

	printf("%zx: ", *addr);
	fputs(instr.mnemonic, stdout);
	fputs(" ", stdout);

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

void parse_ihex_str(size_t *offset, uint16_t len, char *buff) {

	size_t t_length;

	uint8_t data[(len / 2) * sizeof(uint8_t)];
	uint8_t msb, lsb;

	char lsb_buff[3];
	char msb_buff[3];

	for (int i = 0; i < len; i += 4) {

		memcpy(msb_buff, buff + i, 2);
		memcpy(lsb_buff, buff + i + 2, 2);

		msb = strtol(msb_buff, NULL, 16);
		lsb = strtol(lsb_buff, NULL, 16);

		printf("%02X%02X ", lsb, msb);
		data[i / 2]	  = lsb; 
		data[(i / 2) + 1] = msb;
	}

	fputs("\n\n", stdout);
	for (int i = 0; i < sizeof(data) / sizeof(uint8_t); i++) {

		uint32_t opcode = data[i] << 8 | data[i + 1];
		int length = (opcode >> 9) == 0x4a ? 4 : 2;

		if (length == 4) {
			opcode = data[i + 3] << 0  | 
				 data[i + 2] << 8  | 
				 data[i + 1] << 16 | 
				 data[i + 0] << 24;
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

	fputs("\n", stdout);
}

void parse_ihex(char *argv[]) {

	FILE* file = fopen(argv[1], "r");
	if (file == NULL) {
		fprintf(stderr, "ihex2avr: Could not open %s\n", argv[1]);
		exit(EXIT_FAILURE);
	}

	uint8_t  type;
	uint16_t length, address;

	size_t buff_size, offset;

	char flen_buff[2 + 1];
	char addr_buff[4 + 1];
	char type_buff[2 + 1];
	char *data_buff;

	while (!feof(file)) {

		char ch = fgetc(file);
		if (ch != ':') {
			break;
		}
		
		fgets(flen_buff, 3, file);
		fgets(addr_buff, 5, file);
		fgets(type_buff, 3, file);

		length  = strtol(flen_buff, NULL, 16) * 2 + 1;
		address = strtol(addr_buff, NULL, 16);
		type	= strtol(type_buff, NULL, 16);

		if (buff_size == 0) {
			data_buff = (char *) malloc(length);
		} else {
			char *tmp_buff = realloc(data_buff, length);
			if (tmp_buff == NULL) {
				fprintf(stderr, "ihex2avr: Failed to reallocate memory for DATA field\n");
				goto failure;
			}
			data_buff = tmp_buff;
		}

		buff_size = length;
		if (data_buff == NULL) {
			fprintf(stderr, "ihex2avr: failed to allocate memory for DATA field\n");
			goto failure;
		}
		if (fgets(data_buff, length, file) == NULL) {
			fprintf(stderr, "ihex2avr: failed to copy string of %d bytes into a buffer\n", (int) length);
			goto failure;
		};

		printf("Length: %d ",  (int) length - 1);
		printf("Address: %d ", (int) address);
		printf("Type: %d ",    (int) type);
		parse_ihex_str(&offset, length - 1, data_buff);

		for (int i = 0; i < 3; i++) {
			fgetc(file);
		}
	}

	failure:
		free(data_buff);
		fclose(file);
		exit(EXIT_FAILURE);

	free(data_buff);
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

