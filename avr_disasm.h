#include <stdint.h>
#include <stddef.h>
#include "avr_instr.h"

int32_t disasm_operand(int32_t operand, char operand_type);
int32_t operand_bits_from_opcode(uint32_t opcode, uint16_t mask, int length, char operand_type);

void print_db(size_t* addr, uint8_t  byte);
void print_dw(size_t* addr, uint16_t word);

void disasm_instr(size_t* addr, uint32_t opcode, int length, AVR_Instr instr);
void disasm_hexrec(int* temp_len, uint8_t temp_arr[], uint8_t uint_buff[], int len, size_t* offset);
