#include "avr_disasm.h"
#include "avr_parse.h"
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

#define IHEX_REC_TYPE_DATA 0
#define SREC_REC_TYPE_DATA 1

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

void fail(FILE* fp, char *error_message) {
	fprintf(stderr, error_message);
	fclose(fp);
	exit(EXIT_FAILURE);
}

void parse_record(
	int format,
	size_t *offset, 
	uint16_t len, 
	uint8_t checksum, 
	uint8_t type, 
	uint16_t addr, 
	char *rec_buff, 
	uint8_t *uint_buff, 
	FILE *fp) 
{
	uint8_t msb, lsb, sum = 0;
	char lsb_buff[3];
	char msb_buff[3];

	for (int i = 0; i < len; i += 4) {

		memcpy(msb_buff, rec_buff + i, 2);
		memcpy(lsb_buff, rec_buff + i + 2, 2);

		msb = hex_to_int(msb_buff); if (errno != 0) fail(fp, "ihex2avr: hex conversion error");
		lsb = hex_to_int(lsb_buff); if (errno != 0) fail(fp, "ihex2avr: hex conversion error");
		sum = sum + msb + lsb;

		printf("%02X%02X ", lsb, msb);
		uint_buff[i / 2]	   = lsb;
		uint_buff[(i / 2) + 1] = msb;
	}

	fputs("\n\n", stdout);
	sum = format == FORMAT_IHEX ? sum + type + (len / 2) + (addr >> 8) + (addr & 0xff) : 
		  sum + (len / 2 + 3) + (addr >> 8) + (addr & 0xff);

	if (!checksum_cmp(sum, checksum, format)) {
		printf("%02X\n", sum);
		fail(fp, "ihex2avr: checksum mismatch");
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
			instruction	  = AVR_INSTRUCTION_SET[j];

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

void parse_hex(char *argv[], int format) {

	FILE *file = fopen(argv[2], "r");
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
	
	char	rec_start = format == FORMAT_IHEX ? ':' : 'S';;
	char	flen_buff[3];
	char	addr_buff[5];
	char	type_buff[3];
	char	chks_buff[3];
	char	srec_buff[UCHAR_MAX * 2 + 1];
	uint8_t uint_buff[UCHAR_MAX];

	offset = 0;

	while (!feof(file)) {

		char ch = fgetc(file);
		if (ch != rec_start) {
			break;
		}

		if (format == FORMAT_IHEX) {

			if (fgets(flen_buff, 3, file) == NULL) fail(file, "ihex2avr: unexpected EOF\n");
			if (fgets(addr_buff, 5, file) == NULL) fail(file, "ihex2avr: unexpected EOF\n");
			if (fgets(type_buff, 3, file) == NULL) fail(file, "ihex2avr: unexpected EOF\n");

			type   = hex_to_int(type_buff); if (errno != 0) fail(file, "ihex2avr hex conversion error\n");
			disasm = type == IHEX_REC_TYPE_DATA;
		}
		else {

			char result = fgetc(file);
			if (result == EOF) fail(file, "ihex2avr: unexpected EOF\n");
			if (fgets(flen_buff, 3, file) == NULL) fail(file, "ihex2avr: unexpected EOF\n");
			if (fgets(addr_buff, 5, file) == NULL) fail(file, "ihex2avr: unexpected EOF\n");

			type   = hex_to_int(&result); if (errno != 0) fail(file, "ihex2avr hex conversion error\n");
			disasm = type == SREC_REC_TYPE_DATA;
		}

		len		= hex_to_int(flen_buff); if (errno != 0) fail(file, "ihex2avr hex conversion error\n");
		address = hex_to_int(addr_buff); if (errno != 0) fail(file, "ihex2avr hex conversion error\n");
		len		= (len - (format == FORMAT_IHEX ? 0 : 3)) * 2 + 1;

		if (fgets(srec_buff, len, file) == NULL) fail(file, "ihex2avr: failed to read DATA field\n");
		if (fgets(chks_buff, 3, file)	== NULL) fail(file, "ihex2avr: failed to read CHECKSUM field\n");

		if (disasm) {

			printf("Length: %d ", len - 1);
			printf("Address: %d ", address);
			printf("Type: %d ", type);

			checksum = hex_to_int(chks_buff); if (errno != 0) fail(file, "ihex2avr: hex conversion error\n");
			parse_record(format, &offset, len - 1, checksum, type, address, srec_buff, uint_buff, file);
		}
		if (fgetc(file) == '\r') {
			fgetc(file);
		}
	}
	fclose(file);
}


