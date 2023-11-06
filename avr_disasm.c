#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "avr_disasm.h"

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
			operand_disasm = (operand_disasm & (1 << 6)) ? -((~operand_disasm & 0x7f) + 1) : operand_disasm & 0x7f;
			operand_disasm <<= 1;
			break;
		case 'L': // signed pc relative offset from -2048 to 2047} (rjmp)
			operand_disasm = (operand_disasm & (1 << 11)) ? -((~operand_disasm & 0xfff) + 1) : operand_disasm & 0xfff;
			operand_disasm <<= 1;
			break;
	}
	return operand_disasm; 
}

int32_t operand_bits_from_opcode(uint32_t opcode, uint16_t mask, int length, char operand_type) {

	int32_t bits = 0;
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

int disasm_hexrec(int* temp_len, uint8_t temp_arr[], uint8_t uint_buff[], int len, size_t* offset) {

	AVR_Instr avr_instr;
	uint32_t  opcode;

	int  length;
	bool instr = false;

	for (int i = 0; i < len; i++) {

		opcode = uint_buff[i] << 8;
		instr  = false;

		temp_arr[0] = uint_buff[i];
		if ((i + 1) < len) { opcode |= uint_buff[i + 1]; }
		else { *temp_len = 1; return 0; }

		*temp_len = 0;

		for (int j = 0; j < sizeof(AVR_INSTRUCTION_SET) / sizeof(AVR_Instr); j++) {

			avr_instr = AVR_INSTRUCTION_SET[j];
			length    = avr_instr.len;
			instr     = (opcode & avr_instr.opcode_mask) == avr_instr.opcode_bits;

			if (instr) {
				if (length == 32) {

					opcode = uint_buff[i] << 24;

					temp_arr[0] = uint_buff[i + 0];
					if ((i + 1) < len) { opcode |= uint_buff[i + 1] << 16; }
					else { *temp_len = 1; return 0; }

					temp_arr[1] = uint_buff[i + 1];
					if ((i + 2) < len) { opcode |= uint_buff[i + 2] << 8; }
					else { *temp_len = 2; return 0; }

					temp_arr[2] = uint_buff[i + 2];
					if ((i + 3) < len) { opcode |= uint_buff[i + 3] << 0; }
					else { *temp_len = 3; return 0; }

					*temp_len = 0;
				}
				disasm_instr(offset, opcode, length, avr_instr);
				break;
			}
		}
		if (!instr) {
			return 1;
		}
		length /= 8;
		i += length - 1;
		(*offset) += length;
	}
	return 0;
}

void disasm_instr(size_t* addr, uint32_t opcode, int length, AVR_Instr instr) {

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

		get_operand_format(operand_type, operand_format, instr.operands[i]);
		printf(operand_format, operand);
		fputs(" ", stdout);
	}
	fputs("\n", stdout);
}
