# WTL - Zig Linker

A modern linker implementation written in Zig, designed for linking object files and creating executable binaries.

## Overview

WTL (Zig Linker) is a linker that processes object files, resolves symbols, and generates executable binaries. It includes a comprehensive linker script parser for fine-grained control over the linking process, making it suitable for embedded systems development and general-purpose linking tasks.

## Features

- **Linker Script Parser**: Full support for GNU-style linker scripts with lexer, parser, and AST generation
- **Symbol Resolution**: Handles symbol table management and cross-reference resolution
- **Multiple Output Formats**: Support for various executable and object file formats
- **Memory Layout Control**: Precise control over section placement and memory mapping
- **Cross-Platform**: Written in Zig for portability across different architectures
- **Embedded Systems Focus**: Optimized for embedded development workflows

## Architecture

The linker consists of several key components:

- **Lexer/Parser**: Processes linker scripts and builds an Abstract Syntax Tree (AST)
- **Symbol Table Manager**: Handles symbol resolution and relocation
- **Section Manager**: Manages code and data sections
- **Output Generator**: Creates final executable files
- **Memory Layout Engine**: Implements memory region management

## Installation

### Prerequisites

- Zig 0.11.0 or later

### Building from Source

```bash
git clone https://github.com/benmor01/wtl.git
cd wtl
zig build
```

### Running Tests

```bash
zig build test
```

## Usage

### Basic Linking

```bash
wtl -o output_file input1.o input2.o
```

### Using Linker Scripts

```bash
wtl -T linker_script.ld -o firmware.elf startup.o main.o
```

### Example Linker Script

```ld
ENTRY(_start)

MEMORY
{
  rom (rx)  : ORIGIN = 0x08000000, LENGTH = 256K
  ram (rwx) : ORIGIN = 0x20000000, LENGTH = 64K
}

SECTIONS
{
  .text : {
    *(.text*)
    *(.rodata*)
  } > rom

  .data : {
    _data_start = .;
    *(.data*)
    _data_end = .;
  } > ram AT > rom

  .bss : {
    _bss_start = .;
    *(.bss*)
    _bss_end = .;
  } > ram
}
```

## Command Line Options

- `-o <file>` - Specify output file
- `-T <script>` - Use linker script
- `-L <dir>` - Add library search directory
- `-l <lib>` - Link against library
- `--entry <symbol>` - Set entry point
- `--gc-sections` - Remove unused sections
- `--print-map` - Print memory map

## Development

### Project Structure

```
wtl/
├── src/
│   ├── parse.zig          # Linker script parser
│   ├── linker.zig         # Main linker logic
│   ├── symbols.zig        # Symbol table management
│   └── output.zig         # Output file generation
├── tests/
├── examples/
└── README.md
```

### Running the Parser Example

```bash
zig run src/parse.zig
```

This demonstrates the linker script parser with a sample embedded systems linker script.

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

### Development Guidelines

- Follow Zig coding conventions
- Add tests for new functionality
- Update documentation for public APIs
- Ensure cross-platform compatibility

## License

Copyright (c) 2025, Benjamin John Mordaunt

This project is licensed under the MIT License - see the LICENSE file for details.

## Contact

**Benjamin John Mordaunt**
- GitHub: [@benmor01](https://github.com/benmor01)
- Email: [contact information]

## Acknowledgments

- Inspired by GNU ld and LLVM lld
- Built with the Zig programming language
- Designed for embedded systems development
