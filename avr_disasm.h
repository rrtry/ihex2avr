#include <stdint.h>
#include <stddef.h>

#define INSTRUCTIONS 145
#define OPCODE_LEN	 16

typedef struct AVR_Instr {

	char mnemonic[17];
	char operand_types[3];
	char operands[2][5];

	int	len;
	int	argc;

	uint16_t opcode_bits;
	uint16_t opcode_mask;
	uint16_t operand_masks[2];

} AVR_Instr;

extern AVR_Instr AVR_INSTRUCTION_SET[INSTRUCTIONS];

int32_t disasm_operand(int32_t operand, char operand_type);
int32_t operand_bits_from_opcode(uint32_t opcode, uint16_t mask, int length, char operand_type);
void	print_instruction(size_t* addr, uint32_t opcode, int length, AVR_Instr instr);