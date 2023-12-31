﻿#include <stdio.h>
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
#define REC_LEN_BYTES 32
#define REC_LEN_CHARS 64

static int temp_len;
static uint8_t temp_arr[4];
static FILE* file;

static bool checksum_cmp(uint8_t sum, uint8_t checksum, int format) {
	return format != FORMAT_IHEX ? (0xff - (sum & 0xff)) == checksum : ((~sum + 1) & 0xff) == checksum;
}

static uint16_t hex_to_int(char *nptr) {

	char* endptr = NULL;
	errno = 0;
	
	uint16_t i = strtoul(nptr, &endptr, 16);
	if (nptr == endptr || (i == 0 && errno != 0)) {
		fprintf(stderr, "ihex2avr: bad input %s\n", nptr);
		errno = EINVAL;
	}

	return i;
}

static void fail(char *error_message) {
	fputs(error_message, stderr);
	fclose(file);
	exit(EXIT_FAILURE);
}

static void parse_hexrec(
	int	 format,
	size_t*  offset, 
	uint16_t len, 
	uint8_t  checksum, 
	uint8_t  type, 
	uint16_t addr, 
	char*	 rec_buff, 
	uint8_t* uint_buff) 
{
	uint8_t msb, lsb, sum, count = 0;
	char lsb_buff[3];
	char msb_buff[3];

	for (int i = 0; i < len - (len % 4); i += 4) {

		strncpy(msb_buff, rec_buff + i, 2);
		strncpy(lsb_buff, rec_buff + i + 2, 2);

		msb = hex_to_int(msb_buff); if (errno != 0) fail("ihex2avr: hex conversion error\n");
		lsb = hex_to_int(lsb_buff); if (errno != 0) fail("ihex2avr: hex conversion error\n");
		sum = sum + msb + lsb;

#ifdef _DEBUG
		printf("%02X %02X ", msb, lsb);
#endif

		uint_buff[(i / 2) + temp_len]	  = lsb;
		uint_buff[(i / 2) + 1 + temp_len] = msb;
		count += 4;
	}
	if (len % 4 == 2) {
		strncpy(lsb_buff, rec_buff + count, 2);
		lsb = hex_to_int(lsb_buff); if (errno != 0) fail("ihex2avr: hex conversion error\n");
		sum += lsb;
		uint_buff[(count / 2) + temp_len] = lsb;
	}

#ifdef _DEBUG
	printf("\n\n");
#endif

	sum = format == FORMAT_IHEX ? sum + type + (len / 2) + (addr >> 8) + (addr & 0xff) : 
		  sum + (len / 2 + 3) + (addr >> 8) + (addr & 0xff);

	if (!checksum_cmp(sum, checksum, format)) {
		fail("ihex2avr: checksum mismatch");
	}

	memcpy(uint_buff, temp_arr, temp_len);
	disasm_hexrec(&temp_len, temp_arr, uint_buff, (len / 2) + temp_len, offset);
	
#ifdef _DEBUG
	printf("\n");
#endif
}

void parse_hex(char* argv[], int format) {

	if (parse_avr_instructions("avr.txt")) {
		fprintf(stderr, "ihex2avr: failed to parse instructions\n");
		exit(EXIT_FAILURE);
	}

	file = fopen(argv[2], "r");
	if (file == NULL) {
		fprintf(stderr, "ihex2avr: could not open %s\n", argv[2]);
		exit(EXIT_FAILURE);
	}

	bool	 disasm;
	uint8_t  type;
	uint8_t  checksum;

	uint16_t len;
	uint16_t address;
	size_t	 offset;
	
	char	hrec_start = format == FORMAT_IHEX ? ':' : 'S';
	char	flen_buff[3];
	char	addr_buff[5];
	char	type_buff[3];
	char	chks_buff[3];
	char	hrec_buff[REC_LEN_CHARS + 1];
	uint8_t uint_buff[REC_LEN_BYTES + 4];

	offset = 0;

	while (!feof(file)) {

		char ch = fgetc(file);
		if (ch != hrec_start) {
			if (temp_len == 1) print_db(&offset, temp_arr[0]);
			break;
		}

		if (format == FORMAT_IHEX) {

			if (fgets(flen_buff, sizeof flen_buff, file) == NULL) fail("ihex2avr: unexpected EOF\n");
			if (fgets(addr_buff, sizeof addr_buff, file) == NULL) fail("ihex2avr: unexpected EOF\n");
			if (fgets(type_buff, sizeof type_buff, file) == NULL) fail("ihex2avr: unexpected EOF\n");

			type   = hex_to_int(type_buff); if (errno != 0) fail("ihex2avr hex conversion error\n");
			disasm = type == IHEX_REC_TYPE_DATA;
		}
		else {

			char result = fgetc(file);
			if (result == EOF) fail("ihex2avr: unexpected EOF\n");
			if (fgets(flen_buff, sizeof flen_buff, file) == NULL) fail("ihex2avr: unexpected EOF\n");
			if (fgets(addr_buff, sizeof addr_buff, file) == NULL) fail("ihex2avr: unexpected EOF\n");

			type   = hex_to_int(&result); if (errno != 0) fail("ihex2avr hex conversion error\n");
			disasm = type == SREC_REC_TYPE_DATA;
		}

		len = hex_to_int(flen_buff); if (errno != 0) fail("ihex2avr hex conversion error\n");
		address = hex_to_int(addr_buff); if (errno != 0) fail("ihex2avr hex conversion error\n");
		len = (len - (format == FORMAT_IHEX ? 0 : 3)) * 2 + 1;

		if (fgets(hrec_buff, len, file) == NULL) fail("ihex2avr: failed to read DATA field\n");
		if (fgets(chks_buff, sizeof chks_buff, file) == NULL) fail("ihex2avr: failed to read CHECKSUM field\n");

		if (disasm) {

#ifdef _DEBUG
			printf("Length: %d ", len - 1);
			printf("Address: 0x%X ", address);
			printf("Type: 0x%X ", type);	
#endif

			checksum = hex_to_int(chks_buff); if (errno != 0) fail("ihex2avr: hex conversion error\n");
			parse_hexrec(format, &offset, len - 1, checksum, type, address, hrec_buff, uint_buff);
		}
		if (fgetc(file) == '\r') {
			fgetc(file);
		}
	}
	fclose(file);
}


