#include "avr_parse.h"
#include "avr_disasm.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {

	if (argc != 3) {
		fprintf(stderr, "Usage: ihex2avr <format> <file_path>\n");
		return EXIT_FAILURE;
	} 

	int format = -1;
	if (strncmp(argv[1], "ihex", 4) == 0) format = FORMAT_IHEX;
	if (strncmp(argv[1], "srec", 4) == 0) format = FORMAT_SREC;

	if (format == -1) {
		fprintf(stderr, "ihex2avr: unknown file format %s", argv[1]);
		return EXIT_FAILURE;
	} 

	parse_hex(argv, format);
	return EXIT_SUCCESS;
}