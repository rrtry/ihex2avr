#include <stdint.h>

#define INSTRUCTIONS 144
#define OPCODE_LEN   16

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
int parse_avr_instructions(char* f);
