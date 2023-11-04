#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <limits.h>
#include "avr_disasm.h"
#include "avr_parse.h"

#define IHEX_REC_TYPE_DATA 0
#define SREC_REC_TYPE_DATA 1

AVR_Instr AVR_INSTRUCTION_SET[INSTRUCTIONS];

static const char* pointer_regs[] = {
		"X", "Y", "Z",
		"-X", "-Y", "-Z",
		"X+", "Y+", "Z+"
};
static int temp_len;
static uint8_t temp_arr[4];
static FILE* file;

bool is_preg(char* reg);
bool is_disp(char* reg);
bool is_gpr(char* reg);

uint16_t get_opcode_bits(char* opcode);
void	 get_operand_masks(char opcode[17], char operands[2][5], int len, int argc, uint16_t op_masks[2]);
int		 parse_avr_instructions(char* f);

bool checksum_cmp(uint8_t sum, uint8_t checksum, int format) {
	return format != FORMAT_IHEX ? (0xff - (sum & 0xff)) == checksum : ((~sum + 1) & 0xff) == checksum;
}

uint16_t hex_to_int(char *nptr) {

	char* endptr = NULL;
	errno = 0;
	
	uint16_t i = strtoul(nptr, &endptr, 16);
	if (nptr == endptr || (i == 0 && errno != 0)) {
		fprintf(stderr, "ihex2avr: bad input %s\n", nptr);
		errno = EINVAL;
	}

	return i;
}

void fail(char *error_message) {
	fprintf(stderr, error_message);
	fclose(file);
	exit(EXIT_FAILURE);
}

void disasm_hexrec(uint8_t uint_buff[], int len, size_t* offset) {

	AVR_Instr avr_instr;
	uint32_t  opcode;

	int  length;
	bool instr = false;

	for (int i = 0; i < len; i++) {

		opcode = uint_buff[i] << 8;
		instr  = false;

		temp_arr[0] = uint_buff[i];
		if ((i + 1) < len) { opcode |= uint_buff[i + 1]; }
		else { temp_len = 1; return; }

		temp_len = 0;

		for (int j = 0; j < sizeof(AVR_INSTRUCTION_SET) / sizeof(AVR_Instr); j++) {

			avr_instr = AVR_INSTRUCTION_SET[j];
			length	  = avr_instr.len;
			instr	  = (opcode & avr_instr.opcode_mask) == avr_instr.opcode_bits;

			if (instr) {
				if (length == 32) {

					opcode = uint_buff[i] << 24;

					temp_arr[0] = uint_buff[i + 0];
					if ((i + 1) < len) { opcode |= uint_buff[i + 1] << 16; }
					else { temp_len = 1; return; }

					temp_arr[1] = uint_buff[i + 1];
					if ((i + 2) < len) { opcode |= uint_buff[i + 2] << 8; }
					else { temp_len = 2; return; }

					temp_arr[2] = uint_buff[i + 2];
					if ((i + 3) < len) { opcode |= uint_buff[i + 3] << 0; }
					else { temp_len = 3; return; }

					temp_len = 0;
				}
				print_instruction(offset, opcode, length, avr_instr);
				break;
			}
		}
		if (!instr) {
			printf("0x%02X\n", opcode);
			fail("ihex2avr: unknown instruction\n");
		}
		length /= 8;
		i += length - 1;
		(*offset) += length;
	}
}

void parse_hexrec(
	int		 format,
	size_t*  offset, 
	uint16_t len, 
	uint8_t  checksum, 
	uint8_t  type, 
	uint16_t addr, 
	char*	 rec_buff, 
	uint8_t* uint_buff, 
	FILE*	 fp) 
{
	uint8_t msb, lsb, sum = 0;
	char lsb_buff[3];
	char msb_buff[3];

	for (int i = 0; i < len; i += 4) {

		memcpy(msb_buff, rec_buff + i, 2);
		memcpy(lsb_buff, rec_buff + i + 2, 2);

		msb = hex_to_int(msb_buff); if (errno != 0) fail("ihex2avr: hex conversion error");
		lsb = hex_to_int(lsb_buff); if (errno != 0) fail("ihex2avr: hex conversion error");
		sum = sum + msb + lsb;

		uint_buff[(i / 2) + temp_len]	  = lsb;
		uint_buff[(i / 2) + 1 + temp_len] = msb;
	}

	//fputs("\n\n", stdout);
	sum = format == FORMAT_IHEX ? sum + type + (len / 2) + (addr >> 8) + (addr & 0xff) : 
		  sum + (len / 2 + 3) + (addr >> 8) + (addr & 0xff);

	if (!checksum_cmp(sum, checksum, format)) {
		printf("%02X\n", sum);
		fail("ihex2avr: checksum mismatch");
	}

	//fputs("\n", stdout);
	memcpy(uint_buff, temp_arr, temp_len);
	disasm_hexrec(uint_buff, (len / 2) + temp_len, offset);
	//fputs("\n", stdout);
}

void parse_hex(char* argv[], int format) {

	if (parse_avr_instructions("C:\\Users\\user\\Desktop\\avr.txt")) {
		fprintf(stderr, "ihex2avr: failed to parse instructions\n");
		exit(EXIT_FAILURE);
	}

	file = fopen("D:\\ASM\\test\\master_CA_461.hex", "r");
	if (file == NULL) {
		fprintf(stderr, "ihex2avr: could not open %s\n", argv[1]);
		exit(EXIT_FAILURE);
	}

	bool	 disasm;
	uint8_t  type;
	uint8_t  checksum;

	uint16_t len;
	uint16_t address;
	size_t	 offset;
	
	char	hrec_start = format == FORMAT_IHEX ? ':' : 'S';;
	char	flen_buff[3];
	char	addr_buff[5];
	char	type_buff[3];
	char	chks_buff[3];
	char	hrec_buff[UCHAR_MAX * 2 + 1];
	uint8_t uint_buff[UCHAR_MAX];

	offset = 0;

	while (!feof(file)) {

		char ch = fgetc(file);
		if (ch != hrec_start) {
			printf("EOF\n");
			break;
		}

		if (format == FORMAT_IHEX) {

			if (fgets(flen_buff, 3, file) == NULL) fail("ihex2avr: unexpected EOF\n");
			if (fgets(addr_buff, 5, file) == NULL) fail("ihex2avr: unexpected EOF\n");
			if (fgets(type_buff, 3, file) == NULL) fail("ihex2avr: unexpected EOF\n");

			type   = hex_to_int(type_buff); if (errno != 0) fail(file, "ihex2avr hex conversion error\n");
			disasm = type == IHEX_REC_TYPE_DATA;
		}
		else {

			char result = fgetc(file);
			if (result == EOF) fail(file, "ihex2avr: unexpected EOF\n");
			if (fgets(flen_buff, 3, file) == NULL) fail("ihex2avr: unexpected EOF\n");
			if (fgets(addr_buff, 5, file) == NULL) fail("ihex2avr: unexpected EOF\n");

			type   = hex_to_int(&result); if (errno != 0) fail("ihex2avr hex conversion error\n");
			disasm = type == SREC_REC_TYPE_DATA;
		}

		len		= hex_to_int(flen_buff); if (errno != 0) fail("ihex2avr hex conversion error\n");
		address = hex_to_int(addr_buff); if (errno != 0) fail("ihex2avr hex conversion error\n");
		len		= (len - (format == FORMAT_IHEX ? 0 : 3)) * 2 + 1;

		if (fgets(hrec_buff, len, file) == NULL) fail("ihex2avr: failed to read DATA field\n");
		if (fgets(chks_buff, 3, file)	== NULL) fail("ihex2avr: failed to read CHECKSUM field\n");

		if (disasm) {

			/*
			printf("Length: %d ", len - 1);
			printf("Address: 0x%X ", address);
			printf("Type: 0x%X ", type); */

			checksum = hex_to_int(chks_buff); if (errno != 0) fail("ihex2avr: hex conversion error\n");
			parse_hexrec(format, &offset, len - 1, checksum, type, address, hrec_buff, uint_buff, file);
		}
		if (fgetc(file) == '\r') {
			fgetc(file);
		}
	}
	fclose(file);
}

bool is_preg(char* reg) {

	for (int i = 0; i < sizeof(pointer_regs) / sizeof(const char*); i++) {
		if (!strcmp(pointer_regs[i], reg)) {
			return true;
		}
	}

	return false;
}

bool is_disp(char* reg) {
	return !strcmp(reg, "X+q") ||
		   !strcmp(reg, "Y+q") ||
		   !strcmp(reg, "Z+q");
}

bool is_gpr(char* reg) {
	return !strcmp(reg, "Rr") ||
		   !strcmp(reg, "Rd");
}

uint16_t get_opcode_mask(char* opcode) {

	uint16_t mask = 0x0;
	for (int i = OPCODE_LEN - 1; i >= 0; i--) {
		if (opcode[i] == '1' || opcode[i] == '0') {
			mask |= (1 << (OPCODE_LEN - (i + 1)));
		}
	}

	return mask;
}

uint16_t get_opcode_bits(char* opcode) {

	uint16_t bits = 0x0;
	for (int i = OPCODE_LEN - 1; i >= 0; i--) {
		if (opcode[i] == '1') {
			bits |= (1 << (OPCODE_LEN - (i + 1)));
		}
	}

	return bits;
}

void get_operand_masks(char opcode[17], char operands[2][5], int len, int argc, uint16_t op_masks[2]) {

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
	char avr_entry[40];
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
			fprintf(stderr, "sscanf failed\n");
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

		AVR_Instr avr_instr = {
			"", "", { "", "" }, 0, 0, 0, 0, { 0x0, 0x0 }
		}; 

		strcpy(avr_instr.mnemonic,		mnemonic);
		strcpy(avr_instr.operand_types, operand_types);
		strcpy(avr_instr.operands[0],   operands[0]);
		strcpy(avr_instr.operands[1],   operands[1]);

		avr_instr.len  = len;
		avr_instr.argc = argc;
		avr_instr.opcode_bits = opcode_bits;
		avr_instr.opcode_mask = opcode_mask;

		memcpy(avr_instr.operand_masks, operand_masks, sizeof operand_masks);
		AVR_INSTRUCTION_SET[index++] = avr_instr;

		printf("%s %s\t%d\t%d\t0x%02X\t0x%02X\t0x%02X\n", 
		opcode, avr_instr.mnemonic, avr_instr.argc, avr_instr.len, avr_instr.operand_masks[0], avr_instr.operand_masks[1], avr_instr.opcode_bits);

		memset(operands[0], 0, sizeof operands[0]);
		memset(operands[1],	0, sizeof operands[1]);

		memset(operand_masks, 0, sizeof operand_masks);
		memset(instr_args,	  0, sizeof instr_args);
		memset(operand_types, 0, sizeof operand_types);
	}

	fclose(fp); 
	return EXIT_SUCCESS;
}


