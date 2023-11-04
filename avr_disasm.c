#include "avr_disasm.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

/* r   @r{any register}
   d   @r{`ldi' register (r16-r31)}
   v   @r{`movw' even register (r0, r2, ..., r28, r30)}
   a   @r{`fmul' register (r16-r23)}
   w   @r{`adiw' register (r24,r26,r28,r30)}
   e   @r{pointer registers (X,Y,Z)}
   b   @r{base pointer register and displacement ([YZ]+disp)}
   z   @r{Z pointer register (for [e]lpm Rd,Z[+])}
   M   @r{immediate value from 0 to 255}
   n   @r{immediate value from 0 to 255 ( n = ~M ). Relocation impossible}
   s   @r{immediate value from 0 to 7}
   P   @r{Port address value from 0 to 63. (in, out)}
   p   @r{Port address value from 0 to 31. (cbi, sbi, sbic, sbis)}
   K   @r{immediate value from 0 to 63 (used in `adiw', `sbiw')}
   i   @r{immediate value}
   l   @r{signed pc relative offset from -64 to 63}
   L   @r{signed pc relative offset from -2048 to 2047}
   h   @r{absolute code address (call, jmp)}
   S   @r{immediate value from 0 to 7 (S = s << 4)}
   ?   @r{use this opcode entry if no parameters, else use next opcode entry}
*/

void get_operand_format(char operand_type, char format[], char operand[]) {
	switch (operand_type) {

		case 'r':
		case 'd':
		case 'v':
		case 'a':
		case 'w':
			strcpy(format, "r%d");
			break;

		case 'l':
		case 'L':
			strcpy(format, ".%+d");
			break;

		case 's':
		case 'S':
			strcpy(format, "%d");
			break;

		case 'z':
		case 'e':
			strcpy(format, operand);
			break;

		case 'b':
			strncpy(format, operand, 2);
			strcpy(format + 2, "%d");
			break;

		case 'h':
		case 'i':
			strcpy(format, "0x%04X");
			break;

		default:
			strcpy(format, "0x%02X");
	}
}

int32_t disasm_operand(int32_t operand, char operand_type) {
	int32_t operand_disasm = operand;
	switch (operand_type) {
		case 'h': // absolute code address (call, jmp)
			operand_disasm <<= 1;
			break;
		case 'a': // `fmul' register (r16-r23)
		case 'd': // `ldi' register  (r16-r31)
			operand_disasm += 16;
			break;
		case 'v': // `movw' even register (r0, r2, ..., r28, r30)
			operand_disasm *= 2;
			break;
		case 'w': // `adiw' register (r24,r26,r28,r30)
			operand_disasm = 24 + operand_disasm * 2;
			break;
		case 'l': // signed pc relative offset from -64 to 63} (breq)
			operand_disasm = (operand_disasm & (1 << 6)) ? ((-1 << 7) | (operand_disasm & 0x7f)) : operand_disasm & 0x7f;
			operand_disasm <<= 1;
			break;
		case 'L': // signed pc relative offset from -2048 to 2047} (rjmp)
			operand_disasm = (operand_disasm & (1 << 11)) ? ((-1 << 12) | (operand_disasm & 0xfff)) : operand_disasm & 0xfff;
			operand_disasm <<= 1;
			break;
	}
	return operand_disasm; 
}

int32_t operand_bits_from_opcode(uint32_t opcode, uint16_t mask, int length, char operand_type) {

	int32_t bits = 0x0;
	int shift	 = 0;
	bool i32	 = length == 32;

	if (mask != 0x0) {
		for (int i = 0; i < OPCODE_LEN; i++) {
			if ((mask >> i) & 1) {
				if ((opcode >> (i + (i32 ? 16 : 0))) & 1) {
					bits |= (1 << shift);
				}
				shift++;
			}
		}
	}
	if (operand_type == 'i' || operand_type == 'h') {
		bits = (bits << (operand_type == 'h' ? 16 : 0)) | (opcode & 0xffff);
	}
	return bits;
}

void print_instruction(size_t* addr, uint32_t opcode, int length, AVR_Instr instr) {

	printf("%02zx:    ", *addr);
	if (length == 32) {
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

	int32_t  operand;
	uint32_t operand_mask;
	char	 operand_type;
	char	 operand_format[7];

	for (int i = 0; i < instr.argc; i++) {

		operand_type = instr.operand_types[i];
		operand_mask = instr.operand_masks[i];
		operand		 = disasm_operand(
			operand_bits_from_opcode(opcode, operand_mask, length, operand_type),
			operand_type
		);

		get_operand_format(operand_type, operand_format, instr.operands);
		printf(operand_format, operand);
		fputs(" ", stdout);
	}
	fputs("\n", stdout);
}
