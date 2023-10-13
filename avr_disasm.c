#include "avr_disasm.h"
#include <stdio.h>

struct OperandFormat OP_FORMAT[8] = {

	{OPERAND_BRANCH_ADDRESS,   ".%+d"  },
	{OPERAND_BIT,			   "%d"    },
	{OPERAND_RELATIVE_ADDRESS, ".%+d"  },
	{OPERAND_BYTE_ADDRESS,     "0x%02X"},
	{OPERAND_REGISTER,		   "r%d"   },
	{OPERAND_REGISTER_OFFSET,  "r%d"   },
	{OPERAND_IO_REGISTER,	   "0x%02X"},
	{OPERAND_DATA,			   "0x%02X"},

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

int32_t disasm_operand(int32_t operand, int operand_type) {
	int32_t operand_disasm = operand;
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

int32_t operand_bits_from_opcode(uint32_t opcode, uint32_t mask, int length) {

	int32_t bits = 0;
	int shift	 = 0;

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

void print_instruction(size_t* addr, uint32_t opcode, int length, struct Instruction instr) {

	int32_t operand;
	int operand_type;

	printf("%02zx:    ", *addr);
	if (length == 4) {
		printf("%02x %02x %02x %02x    ",
			opcode >> 24, (opcode >> 16) & 0xff, (opcode >> 8) & 0xff, opcode & 0xff
		);
	}
	else {
		printf("%02x %02x    ", (opcode >> 8) & 0xff, opcode & 0xff);
		fputs("      ", stdout);
	}

	fputs(instr.mnemonic, stdout);
	fputs(strlen(instr.mnemonic) == 4 ? "   " : "    ", stdout);

	for (int i = 0; i < instr.operands; i++) {

		operand_type = instr.operand_type[i];
		operand		 = disasm_operand(operand_bits_from_opcode(opcode, instr.operand_mask[i], length), operand_type);

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