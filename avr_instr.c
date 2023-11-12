#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include "avr_instr.h"

AVR_Instr AVR_INSTRUCTION_SET[INSTRUCTIONS];
static const char* pointer_regs[] = {
		"X", "Y", "Z",
		"-X", "-Y", "-Z",
		"X+", "Y+", "Z+"
};

static bool is_preg(char* reg) {

	for (int i = 0; i < sizeof(pointer_regs) / sizeof(const char*); i++) {
		if (!strcmp(pointer_regs[i], reg)) {
			return true;
		}
	}

	return false;
}

static bool is_disp(char* reg) {
	return !strcmp(reg, "X+q") ||
	       !strcmp(reg, "Y+q") ||
	       !strcmp(reg, "Z+q");
}

static bool is_gpr(char* reg) {
	return !strcmp(reg, "Rr") ||
	       !strcmp(reg, "Rd");
}

static uint16_t get_opcode_mask(char* opcode) {

	uint16_t mask = 0x0;
	for (int i = OPCODE_LEN - 1; i >= 0; i--) {
		if (opcode[i] == '1' || opcode[i] == '0') {
			mask |= (1 << (OPCODE_LEN - (i + 1)));
		}
	}

	return mask;
}

static uint16_t get_opcode_bits(char* opcode) {

	uint16_t bits = 0x0;
	for (int i = OPCODE_LEN - 1; i >= 0; i--) {
		if (opcode[i] == '1') {
			bits |= (1 << (OPCODE_LEN - (i + 1)));
		}
	}

	return bits;
}

static void get_operand_masks(char opcode[17], char operands[2][5], int len, int argc, uint16_t op_masks[2]) {

	char operand;
	bool i32  = len == 32;
	bool regs = true;
	bool gpr  = false;
	bool disp = false;

	for (int i = 0; i < argc; i++) {
		regs &= is_gpr(operands[i]);
	}
	if (regs && argc == 1) {
		regs = false;
	}

	for (int j = 0; j < argc; j++) {

		if (is_preg(operands[j])) {
			continue;
		}

		gpr  = is_gpr(operands[j]);
		disp = is_disp(operands[j]);

		if (disp) operand = operands[j][2];
		else if (gpr) operand = operands[j][1];
		else operand = operands[j][0];

		if (operand == '0') {
			continue;
		}

		for (int i = OPCODE_LEN - 1; i >= 0; i--) {
			if (opcode[i] == operand || (!regs && gpr && (opcode[i] == 'd' || opcode[i] == 'r'))) {
				op_masks[j] |= 1 << (OPCODE_LEN - (i + 1));
			}
		}
	}
}

int parse_avr_instructions(char* f) {

	FILE* fp = fopen(f, "r");
	if (fp == NULL) {
		fprintf(stderr, "ihex2avr: fopen failed\n");
		return EXIT_FAILURE;
	}

	uint16_t opcode_bits = 0x0;
	uint16_t opcode_mask = 0x0;
	uint16_t operand_masks[2] = { 0x0, 0x0 };

	int index;
	int result;
	int len;
	int argc;

	char* token = NULL;

	char operands[2][5];
	char avr_entry[41];
	char operand_types[3];
	char opcode[17];
	char mnemonic[7];
	char instr_args[7];

	index = 0;
	while (!feof(fp)) {

		if (fgets(avr_entry, sizeof avr_entry, fp) == NULL) {
			fprintf(stderr, "fgets failed\n");
			fclose(fp);
			return EXIT_FAILURE;
		}

		result = sscanf(avr_entry, "%s %d %d %s %s %s\n", opcode, &len, &argc, mnemonic, instr_args, operand_types);
		if (result < 4) {
			fprintf(stderr, "sscanf failed %d\n", result);
			fclose(fp);
			return EXIT_FAILURE;
		}

		token = strtok(instr_args, ",");
		if (token != NULL) strcpy(operands[0], token);

		token = strtok(NULL, ",");
		if (token != NULL) strcpy(operands[1], token);

		opcode_bits = get_opcode_bits(opcode);
		opcode_mask = get_opcode_mask(opcode);
		get_operand_masks(opcode, operands, len, argc, operand_masks);

		AVR_Instr avr_instr;

		strcpy(avr_instr.mnemonic, mnemonic);
		strcpy(avr_instr.operand_types, operand_types);
		strcpy(avr_instr.operands[0], operands[0]);
		strcpy(avr_instr.operands[1], operands[1]);

		avr_instr.len  = len;
		avr_instr.argc = argc;
		avr_instr.opcode_bits = opcode_bits;
		avr_instr.opcode_mask = opcode_mask;

		memcpy(avr_instr.operand_masks, operand_masks, sizeof operand_masks);
		AVR_INSTRUCTION_SET[index++] = avr_instr;

#ifdef _DEBUG
		printf("%s %s\t%d\t%d\t0x%02X\t0x%02X\t0x%02X\n",
			opcode, avr_instr.mnemonic, avr_instr.argc, avr_instr.len, avr_instr.operand_masks[0], avr_instr.operand_masks[1], avr_instr.opcode_bits);
#endif

		memset(operands[0], 0, sizeof operands[0]);
		memset(operands[1], 0, sizeof operands[1]);

		memset(operand_masks, 0, sizeof operand_masks);
		memset(instr_args,    0, sizeof instr_args);
		memset(operand_types, 0, sizeof operand_types);
	}
	fclose(fp);
	return EXIT_SUCCESS;
}
