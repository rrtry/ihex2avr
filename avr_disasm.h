#include <stdint.h>
#include <stddef.h>

#define OPERAND_NONE		 0x00
#define OPERAND_REGISTER	 0x01
#define OPERAND_REGISTER_OFFSET  0x02
#define OPERAND_BYTE_ADDRESS	 0x04
#define OPERAND_RELATIVE_ADDRESS 0x08
#define OPERAND_BRANCH_ADDRESS	 0x10
#define OPERAND_IO_REGISTER	 0x20
#define OPERAND_DATA		 0x40
#define OPERAND_BIT		 0x80

typedef struct Instruction {
	char mnemonic[5];
	int  operands;
	uint32_t operand_mask[2];
	int operand_type[2];
	uint32_t instruction_mask;
} instruction;

typedef struct OperandFormat {
	int operand_type;
	char format[7];
} operand_format;

extern struct OperandFormat OP_FORMAT[8];
extern struct Instruction AVR_INSTRUCTION_SET[14];

int32_t disasm_operand(int32_t operand, int operand_type);
int32_t operand_bits_from_opcode(uint32_t opcode, uint32_t mask, int length);
void print_instruction(size_t* addr, uint32_t opcode, int length, struct Instruction instr);
