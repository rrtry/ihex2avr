# CMakeList.txt : CMake project for ihex2avr, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("ihex2avr")

# Add source to this project's executable.
add_executable (ihex2avr "avr_parse.c"  "avr_disasm.h" "avr_disasm.c"  "avr_main.c"    "avr_parse.h" "avr_instr.c" "avr_instr.h")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET ihex2avr PROPERTY CXX_STANDARD 20)
endif()

if(MSVC)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()

if (${CMAKE_BUILD_TYPE} STREQUAL Debug)
    set_directory_properties(PROPERTIES COMPILE_DEFINITIONS "_DEBUG")
else ()
    set_directory_properties(PROPERTIES COMPILE_DEFINITIONS "RELEASE")
endif ()

# TODO: Add tests and install targets if needed.
