//! Copyright (c) 2025, Benjamin John Mordaunt
//!
//! wtl Linker Project
//!

const std = @import("std");
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;
const HashMap = std.HashMap;
const StringHashMap = std.StringHashMap;

// Token types for the lexer
pub const TokenType = enum {
    // Literals
    identifier,
    number,
    string,

    // Keywords
    entry,
    include,
    input,
    group,
    as_needed,
    output,
    search_dir,
    startup,
    output_format,
    output_arch,
    sections,
    memory,
    phdrs,
    version,
    @"extern",
    provide,
    provide_hidden,
    keep,
    sort,
    sort_by_name,
    sort_by_alignment,
    sort_by_init_priority,
    @"align",
    subalign,
    only_if_ro,
    only_if_rw,
    special,
    origin,
    length,
    assert_kw,

    // Operators and punctuation
    assign, // =
    add_assign, // +=
    sub_assign, // -=
    mul_assign, // *=
    div_assign, // /=
    lshift_assign, // <<=
    rshift_assign, // >>=
    and_assign, // &=
    or_assign, // |=
    plus, // +
    minus, // -
    multiply, // *
    divide, // /
    modulo, // %
    bitwise_and, // &
    bitwise_or, // |
    bitwise_xor, // ^
    bitwise_not, // ~
    logical_and, // &&
    logical_or, // ||
    logical_not, // !
    left_shift, // <<
    right_shift, // >>
    equal, // ==
    not_equal, // !=
    less_than, // <
    less_equal, // <=
    greater_than, // >
    greater_equal, // >=
    question, // ?
    colon, // :
    semicolon, // ;
    comma, // ,
    dot, // .
    left_paren, // (
    right_paren, // )
    left_brace, // {
    right_brace, // }
    left_bracket, // [
    right_bracket, // ]

    // Special
    eof,
    newline,
    comment,
};

pub const Token = struct {
    type: TokenType,
    lexeme: []const u8,
    line: u32,
    column: u32,
};

// AST Node types
pub const AstNodeType = enum {
    script,
    entry_command,
    include_command,
    input_command,
    group_command,
    output_command,
    search_dir_command,
    startup_command,
    output_format_command,
    output_arch_command,
    sections_command,
    memory_command,
    phdrs_command,
    version_command,
    assignment,
    provide,
    expression,
    section_definition,
    memory_region,
    program_header,
    version_script,
    keep_command,
    sort_command,
    align_command,
    assert_command,
    provide_command,
    binary_op,
    unary_op,
    function_call,
    identifier,
    number,
    string_literal,
    location_counter,
};

pub const Expression = union(enum) {
    binary_op: struct {
        left: *Expression,
        operator: TokenType,
        right: *Expression,
    },
    unary_op: struct {
        operator: TokenType,
        operand: *Expression,
    },
    ternary: struct {
        condition: *Expression,
        true_expr: *Expression,
        false_expr: *Expression,
    },
    function_call: struct {
        name: []const u8,
        args: ArrayList(*Expression),
    },
    identifier: []const u8,
    number: u64,
    string: []const u8,
    location_counter,
};

pub const SectionDefinition = struct {
    name: []const u8,
    address: ?*Expression,
    type_info: ?[]const u8,
    contents: ArrayList(SectionContent),
    at_address: ?*Expression,
    align_expr: ?*Expression,
    subalign_expr: ?*Expression,
    constraint: ?*Expression,
    fill_expr: ?*Expression,
    region: ?[]const u8,
    lma_region: ?[]const u8,
    phdr_list: ArrayList([]const u8),
};

pub const SectionContent = union(enum) {
    assignment: Assignment,
    input_section: InputSection,
    keep_command: KeepCommand,
    sort_command: SortCommand,
    align_command: AlignCommand,
    assert_command: AssertCommand,
    fill: *Expression,
    constructors,
    destructors,
};

pub const InputSection = struct {
    file_spec: ?[]const u8,
    section_spec: ArrayList([]const u8),
    exclude_files: ArrayList([]const u8),
    sort_type: ?SortType,
};

pub const KeepCommand = struct {
    input_sections: ArrayList(InputSection),
};

pub const SortCommand = struct {
    sort_type: SortType,
    input_sections: ArrayList(InputSection),
};

pub const SortType = enum {
    by_name,
    by_alignment,
    by_init_priority,
    none,
};

pub const AlignCommand = struct {
    expr: *Expression,
    fill: ?*Expression,
};

pub const AssertCommand = struct {
    condition: *Expression,
    message: ?[]const u8,
};

pub const Assignment = struct {
    target: []const u8,
    operator: TokenType,
    value: *Expression,
    provide: bool,
    hidden: bool,
};

pub const MemoryRegion = struct {
    name: []const u8,
    attributes: []const u8,
    origin: *Expression,
    length: *Expression,
};

pub const ProgramHeader = struct {
    name: []const u8,
    type_expr: *Expression,
    filehdr: bool,
    phdrs: bool,
    at_expr: ?*Expression,
    flags_expr: ?*Expression,
};

pub const AstNode = struct {
    type: AstNodeType,
    data: union {
        script: ArrayList(*AstNode),
        entry: []const u8,
        include: []const u8,
        input: ArrayList([]const u8),
        group: ArrayList([]const u8),
        output: []const u8,
        search_dir: []const u8,
        startup: []const u8,
        output_format: struct {
            bfd_name: []const u8,
            big_endian: ?[]const u8,
            little_endian: ?[]const u8,
        },
        output_arch: []const u8,
        sections: ArrayList(SectionDefinition),
        memory: ArrayList(MemoryRegion),
        phdrs: ArrayList(ProgramHeader),
        assignment: Assignment,
        expression: Expression,
        section_def: SectionDefinition,
        memory_region: MemoryRegion,
        program_header: ProgramHeader,
        provide: Assignment,
    },
    line: u32,
    column: u32,
};

// Lexer implementation
pub const Lexer = struct {
    input: []const u8,
    position: usize,
    current: usize,
    line: u32,
    column: u32,
    allocator: Allocator,
    keywords: StringHashMap(TokenType),

    const Self = @This();

    pub fn init(allocator: Allocator, input: []const u8) !Self {
        var keywords = StringHashMap(TokenType).init(allocator);
        try keywords.put("ENTRY", .entry);
        try keywords.put("INCLUDE", .include);
        try keywords.put("INPUT", .input);
        try keywords.put("GROUP", .group);
        try keywords.put("AS_NEEDED", .as_needed);
        try keywords.put("OUTPUT", .output);
        try keywords.put("SEARCH_DIR", .search_dir);
        try keywords.put("STARTUP", .startup);
        try keywords.put("OUTPUT_FORMAT", .output_format);
        try keywords.put("OUTPUT_ARCH", .output_arch);
        try keywords.put("SECTIONS", .sections);
        try keywords.put("MEMORY", .memory);
        try keywords.put("PHDRS", .phdrs);
        try keywords.put("VERSION", .version);
        try keywords.put("EXTERN", .@"extern");
        try keywords.put("PROVIDE", .provide);
        try keywords.put("PROVIDE_HIDDEN", .provide_hidden);
        try keywords.put("KEEP", .keep);
        try keywords.put("SORT", .sort);
        try keywords.put("SORT_BY_NAME", .sort_by_name);
        try keywords.put("SORT_BY_ALIGNMENT", .sort_by_alignment);
        try keywords.put("SORT_BY_INIT_PRIORITY", .sort_by_init_priority);
        try keywords.put("ALIGN", .@"align");
        try keywords.put("SUBALIGN", .subalign);
        try keywords.put("ONLY_IF_RO", .only_if_ro);
        try keywords.put("ONLY_IF_RW", .only_if_rw);
        try keywords.put("SPECIAL", .special);
        try keywords.put("ORIGIN", .origin);
        try keywords.put("LENGTH", .length);
        try keywords.put("ASSERT", .assert_kw);

        return Self{
            .input = input,
            .position = 0,
            .current = 0,
            .line = 1,
            .column = 1,
            .allocator = allocator,
            .keywords = keywords,
        };
    }

    pub fn deinit(self: *Self) void {
        self.keywords.deinit();
    }

    pub fn scanToken(self: *Self) !Token {
        self.skipWhitespace();

        self.position = self.current;

        if (self.isAtEnd()) {
            return self.makeToken(.eof);
        }

        const c = self.advance();

        if (std.ascii.isAlphabetic(c) or c == '_' or c == '.') {
            return self.identifier();
        }

        if (std.ascii.isDigit(c)) {
            return self.number();
        }

        return switch (c) {
            '(' => self.makeToken(.left_paren),
            ')' => self.makeToken(.right_paren),
            '{' => self.makeToken(.left_brace),
            '}' => self.makeToken(.right_brace),
            '[' => self.makeToken(.left_bracket),
            ']' => self.makeToken(.right_bracket),
            ',' => self.makeToken(.comma),
            '.' => self.makeToken(.dot),
            ';' => self.makeToken(.semicolon),
            ':' => self.makeToken(.colon),
            '?' => self.makeToken(.question),
            '~' => self.makeToken(.bitwise_not),
            '+' => if (self.match('=')) self.makeToken(.add_assign) else self.makeToken(.plus),
            '-' => if (self.match('=')) self.makeToken(.sub_assign) else self.makeToken(.minus),
            '*' => if (self.match('=')) self.makeToken(.mul_assign) else self.makeToken(.multiply),
            '/' => if (self.match('=')) self.makeToken(.div_assign) else if (self.match('*')) self.blockComment() else self.makeToken(.divide),
            '%' => self.makeToken(.modulo),
            '^' => self.makeToken(.bitwise_xor),
            '!' => if (self.match('=')) self.makeToken(.not_equal) else self.makeToken(.logical_not),
            '=' => if (self.match('=')) self.makeToken(.equal) else self.makeToken(.assign),
            '<' => if (self.match('<')) {
                return if (self.match('=')) self.makeToken(.lshift_assign) else self.makeToken(.left_shift);
            } else if (self.match('=')) {
                return self.makeToken(.less_equal);
            } else {
                return self.makeToken(.less_than);
            },
            '>' => if (self.match('>')) {
                return if (self.match('=')) self.makeToken(.rshift_assign) else self.makeToken(.right_shift);
            } else if (self.match('=')) {
                return self.makeToken(.greater_equal);
            } else {
                return self.makeToken(.greater_than);
            },
            '&' => if (self.match('&')) {
                return self.makeToken(.logical_and);
            } else if (self.match('=')) {
                return self.makeToken(.and_assign);
            } else {
                return self.makeToken(.bitwise_and);
            },
            '|' => if (self.match('|')) {
                return self.makeToken(.logical_or);
            } else if (self.match('=')) {
                return self.makeToken(.or_assign);
            } else {
                return self.makeToken(.bitwise_or);
            },
            '"' => self.string(),
            '\n' => {
                const token = self.makeToken(.newline);
                self.line += 1;
                self.column = 1;
                return token;
            },
            else => error.UnexpectedCharacter,
        };
    }

    fn isAtEnd(self: *Self) bool {
        return self.current >= self.input.len;
    }

    fn advance(self: *Self) u8 {
        const c = self.input[self.current];
        self.current += 1;
        self.column += 1;
        return c;
    }

    fn match(self: *Self, expected: u8) bool {
        if (self.isAtEnd()) return false;
        if (self.input[self.current] != expected) return false;
        self.current += 1;
        self.column += 1;
        return true;
    }

    fn peek(self: *Self) u8 {
        if (self.isAtEnd()) return 0;
        return self.input[self.current];
    }

    fn peekNext(self: *Self) u8 {
        if (self.current + 1 >= self.input.len) return 0;
        return self.input[self.current + 1];
    }

    fn makeToken(self: *Self, token_type: TokenType) Token {
        return Token{
            .type = token_type,
            .lexeme = self.input[self.position..self.current],
            .line = self.line,
            .column = self.column - @as(u32, @intCast(self.current - self.position)),
        };
    }

    fn skipWhitespace(self: *Self) void {
        while (true) {
            const c = self.peek();
            switch (c) {
                ' ', '\r', '\t' => {
                    _ = self.advance();
                },
                '\n' => {
                    self.line += 1;
                    self.column = 1;
                    _ = self.advance();
                },
                '#' => {
                    // Line comment
                    while (self.peek() != '\n' and !self.isAtEnd()) {
                        _ = self.advance();
                    }
                },
                else => break,
            }
        }
    }

    fn string(self: *Self) !Token {
        while (self.peek() != '"' and !self.isAtEnd()) {
            if (self.peek() == '\n') {
                self.line += 1;
                self.column = 1;
            }
            if (self.peek() == '\\') {
                _ = self.advance(); // Skip escape character
                if (!self.isAtEnd()) {
                    _ = self.advance(); // Skip escaped character
                }
            } else {
                _ = self.advance();
            }
        }

        if (self.isAtEnd()) return error.UnterminatedString;

        // Consume the closing quote
        _ = self.advance();
        return self.makeToken(.string);
    }

    fn number(self: *Self) Token {
        // Handle hexadecimal
        if (self.input[self.current - 1] == '0' and (self.peek() == 'x' or self.peek() == 'X')) {
            _ = self.advance(); // consume 'x'
            while (std.ascii.isHex(self.peek())) {
                _ = self.advance();
            }
            return self.makeToken(.number);
        }

        // Handle octal
        if (self.input[self.current - 1] == '0') {
            while (self.peek() >= '0' and self.peek() <= '7') {
                _ = self.advance();
            }
            return self.makeToken(.number);
        }

        // Handle decimal
        while (std.ascii.isDigit(self.peek())) {
            _ = self.advance();
        }

        // Handle suffixes like K, M, G
        if (self.peek() == 'K' or self.peek() == 'M' or self.peek() == 'G') {
            _ = self.advance();
        }

        return self.makeToken(.number);
    }

    fn identifier(self: *Self) Token {
        while (std.ascii.isAlphanumeric(self.peek()) or self.peek() == '_' or self.peek() == '.' or self.peek() == '$') {
            _ = self.advance();
        }

        const text = self.input[self.position..self.current];
        const token_type = self.keywords.get(text) orelse .identifier;
        return Token{
            .type = token_type,
            .lexeme = text,
            .line = self.line,
            .column = self.column - @as(u32, @intCast(self.current - self.position)),
        };
    }

    fn blockComment(self: *Self) !Token {
        var nesting: u32 = 1;

        while (nesting > 0 and !self.isAtEnd()) {
            if (self.peek() == '/' and self.peekNext() == '*') {
                _ = self.advance();
                _ = self.advance();
                nesting += 1;
            } else if (self.peek() == '*' and self.peekNext() == '/') {
                _ = self.advance();
                _ = self.advance();
                nesting -= 1;
            } else {
                if (self.peek() == '\n') {
                    self.line += 1;
                    self.column = 1;
                }
                _ = self.advance();
            }
        }

        if (nesting > 0) return error.UnterminatedComment;
        return self.makeToken(.comment);
    }
};

// Parser implementation
pub const Parser = struct {
    lexer: *Lexer,
    current: Token,
    previous: Token,
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, lexer: *Lexer) !Self {
        var parser = Self{
            .lexer = lexer,
            .current = undefined,
            .previous = undefined,
            .allocator = allocator,
        };

        try parser.advance();
        return parser;
    }

    pub fn parse(self: *Self) !*AstNode {
        var commands = ArrayList(*AstNode).init(self.allocator);

        while (!self.isAtEnd()) {
            // Skip newlines and comments
            if (self.current.type == .newline or self.current.type == .comment) {
                try self.advance();
                continue;
            }

            if (try self.parseCommand()) |command| {
                try commands.append(command);
            }
        }

        const script_node = try self.allocator.create(AstNode);
        script_node.* = AstNode{
            .type = .script,
            .data = .{ .script = commands },
            .line = 1,
            .column = 1,
        };

        return script_node;
    }

    fn parseCommand(self: *Self) !?*AstNode {
        return switch (self.current.type) {
            .entry => self.parseEntry(),
            .include => self.parseInclude(),
            .input => self.parseInput(),
            .group => self.parseGroup(),
            .output => self.parseOutput(),
            .search_dir => self.parseSearchDir(),
            .startup => self.parseStartup(),
            .output_format => self.parseOutputFormat(),
            .output_arch => self.parseOutputArch(),
            .sections => self.parseSections(),
            .memory => self.parseMemory(),
            .phdrs => self.parsePhdrs(),
            .provide, .provide_hidden => self.parseProvide(),
            .identifier => self.parseAssignment(),
            else => {
                try self.advance();
                return null;
            },
        };
    }

    fn parseEntry(self: *Self) !*AstNode {
        const line = self.current.line;
        const column = self.current.column;

        try self.consume(.entry, "Expected 'ENTRY'");
        try self.consume(.left_paren, "Expected '(' after ENTRY");

        const entry_name = try self.consumeIdentifier("Expected entry point name");

        try self.consume(.right_paren, "Expected ')' after entry point");
        _ = try self.consumeOptional(.semicolon);

        const node = try self.allocator.create(AstNode);
        node.* = AstNode{
            .type = .entry_command,
            .data = .{ .entry = entry_name },
            .line = line,
            .column = column,
        };

        return node;
    }

    fn parseInclude(self: *Self) !*AstNode {
        const line = self.current.line;
        const column = self.current.column;

        try self.consume(.include, "Expected 'INCLUDE'");
        const filename = try self.consumeString("Expected filename");
        _ = try self.consumeOptional(.semicolon);

        const node = try self.allocator.create(AstNode);
        node.* = AstNode{
            .type = .include_command,
            .data = .{ .include = filename },
            .line = line,
            .column = column,
        };

        return node;
    }

    fn parseInput(self: *Self) !*AstNode {
        const line = self.current.line;
        const column = self.current.column;

        try self.consume(.input, "Expected 'INPUT'");
        try self.consume(.left_paren, "Expected '(' after INPUT");

        var files = ArrayList([]const u8).init(self.allocator);

        while (!self.check(.right_paren) and !self.isAtEnd()) {
            const filename = try self.consumeString("Expected filename");
            try files.append(filename);
            _ = try self.consumeOptional(.comma);
        }

        try self.consume(.right_paren, "Expected ')' after file list");
        _ = try self.consumeOptional(.semicolon);

        const node = try self.allocator.create(AstNode);
        node.* = AstNode{
            .type = .input_command,
            .data = .{ .input = files },
            .line = line,
            .column = column,
        };

        return node;
    }

    fn parseGroup(self: *Self) !*AstNode {
        const line = self.current.line;
        const column = self.current.column;

        try self.consume(.group, "Expected 'GROUP'");
        try self.consume(.left_paren, "Expected '(' after GROUP");

        var files = ArrayList([]const u8).init(self.allocator);

        while (!self.check(.right_paren) and !self.isAtEnd()) {
            if (self.check(.as_needed)) {
                try self.advance();
                try self.consume(.left_paren, "Expected '(' after AS_NEEDED");

                while (!self.check(.right_paren) and !self.isAtEnd()) {
                    const filename = try self.consumeString("Expected filename");
                    try files.append(filename);
                    _ = try self.consumeOptional(.comma);
                }

                try self.consume(.right_paren, "Expected ')' after AS_NEEDED files");
            } else {
                const filename = try self.consumeString("Expected filename");
                try files.append(filename);
            }
            _ = try self.consumeOptional(.comma);
        }

        try self.consume(.right_paren, "Expected ')' after group");
        _ = try self.consumeOptional(.semicolon);

        const node = try self.allocator.create(AstNode);
        node.* = AstNode{
            .type = .group_command,
            .data = .{ .group = files },
            .line = line,
            .column = column,
        };

        return node;
    }

    fn parseOutput(self: *Self) !*AstNode {
        const line = self.current.line;
        const column = self.current.column;

        try self.consume(.output, "Expected 'OUTPUT'");
        try self.consume(.left_paren, "Expected '(' after OUTPUT");

        const filename = try self.consumeString("Expected output filename");

        try self.consume(.right_paren, "Expected ')' after filename");
        _ = try self.consumeOptional(.semicolon);

        const node = try self.allocator.create(AstNode);
        node.* = AstNode{
            .type = .output_command,
            .data = .{ .output = filename },
            .line = line,
            .column = column,
        };

        return node;
    }

    fn parseSearchDir(self: *Self) !*AstNode {
        const line = self.current.line;
        const column = self.current.column;

        try self.consume(.search_dir, "Expected 'SEARCH_DIR'");
        try self.consume(.left_paren, "Expected '(' after SEARCH_DIR");

        const dirname = try self.consumeString("Expected directory name");

        try self.consume(.right_paren, "Expected ')' after directory");
        _ = try self.consumeOptional(.semicolon);

        const node = try self.allocator.create(AstNode);
        node.* = AstNode{
            .type = .search_dir_command,
            .data = .{ .search_dir = dirname },
            .line = line,
            .column = column,
        };

        return node;
    }

    fn parseStartup(self: *Self) !*AstNode {
        const line = self.current.line;
        const column = self.current.column;

        try self.consume(.startup, "Expected 'STARTUP'");
        try self.consume(.left_paren, "Expected '(' after STARTUP");

        const filename = try self.consumeString("Expected startup filename");

        try self.consume(.right_paren, "Expected ')' after filename");
        _ = try self.consumeOptional(.semicolon);

        const node = try self.allocator.create(AstNode);
        node.* = AstNode{
            .type = .startup_command,
            .data = .{ .startup = filename },
            .line = line,
            .column = column,
        };

        return node;
    }

    fn parseOutputFormat(self: *Self) !*AstNode {
        const line = self.current.line;
        const column = self.current.column;

        try self.consume(.output_format, "Expected 'OUTPUT_FORMAT'");
        try self.consume(.left_paren, "Expected '(' after OUTPUT_FORMAT");

        const bfd_name = try self.consumeString("Expected BFD name");
        var big_endian: ?[]const u8 = null;
        var little_endian: ?[]const u8 = null;

        if (try self.consumeOptional(.comma)) {
            big_endian = try self.consumeString("Expected big-endian format");
            if (try self.consumeOptional(.comma)) {
                little_endian = try self.consumeString("Expected little-endian format");
            }
        }

        try self.consume(.right_paren, "Expected ')' after format");
        _ = try self.consumeOptional(.semicolon);

        const node = try self.allocator.create(AstNode);
        node.* = AstNode{
            .type = .output_format_command,
            .data = .{ .output_format = .{
                .bfd_name = bfd_name,
                .big_endian = big_endian,
                .little_endian = little_endian,
            } },
            .line = line,
            .column = column,
        };

        return node;
    }

    fn parseOutputArch(self: *Self) !*AstNode {
        const line = self.current.line;
        const column = self.current.column;

        try self.consume(.output_arch, "Expected 'OUTPUT_ARCH'");
        try self.consume(.left_paren, "Expected '(' after OUTPUT_ARCH");

        const arch = try self.consumeString("Expected architecture name");

        try self.consume(.right_paren, "Expected ')' after architecture");
        _ = try self.consumeOptional(.semicolon);

        const node = try self.allocator.create(AstNode);
        node.* = AstNode{
            .type = .output_arch_command,
            .data = .{ .output_arch = arch },
            .line = line,
            .column = column,
        };

        return node;
    }

    fn parseSections(self: *Self) !*AstNode {
        const line = self.current.line;
        const column = self.current.column;

        try self.consume(.sections, "Expected 'SECTIONS'");
        try self.consume(.left_brace, "Expected '{' after SECTIONS");

        var sections = ArrayList(SectionDefinition).init(self.allocator);

        while (!self.check(.right_brace) and !self.isAtEnd()) {
            if (self.current.type == .newline or self.current.type == .comment) {
                try self.advance();
                continue;
            }

            // Parse section definition or assignment
            if (self.check(.identifier)) {
                // Look ahead to see if this is an assignment or section definition
                // This is a simplified heuristic - in a real parser you'd need better lookahead
                if (self.peekAssignment()) {
                    _ = try self.parseAssignment();
                } else {
                    const section = try self.parseSectionDefinition();
                    try sections.append(section);
                }
            } else {
                try self.advance(); // Skip unknown tokens
            }
        }

        try self.consume(.right_brace, "Expected '}' after SECTIONS");
        _ = try self.consumeOptional(.semicolon);

        const node = try self.allocator.create(AstNode);
        node.* = AstNode{
            .type = .sections_command,
            .data = .{ .sections = sections },
            .line = line,
            .column = column,
        };

        return node;
    }

    fn parseSectionDefinition(self: *Self) !SectionDefinition {
        const name = try self.consumeIdentifier("Expected section name");

        var address: ?*Expression = null;
        var type_info: ?[]const u8 = null;
        var at_address: ?*Expression = null;
        var align_expr: ?*Expression = null;
        var subalign_expr: ?*Expression = null;
        var constraint: ?*Expression = null;
        const fill_expr: ?*Expression = null;
        var region: ?[]const u8 = null;
        const lma_region: ?[]const u8 = null;
        var phdr_list = ArrayList([]const u8).init(self.allocator);
        var contents = ArrayList(SectionContent).init(self.allocator);

        // Parse optional address
        if (!self.check(.colon) and !self.check(.left_brace)) {
            if (self.check(.number) or self.check(.identifier) or self.check(.left_paren) or self.check(.dot)) {
                address = try self.parseExpression();
            }
        }

        // Parse optional type info
        if (self.check(.left_paren)) {
            try self.advance();
            if (self.check(.identifier)) {
                type_info = self.current.lexeme;
                try self.advance();
            }
            try self.consume(.right_paren, "Expected ')' after type info");
        }

        try self.consume(.colon, "Expected ':' after section name");
        try self.consume(.left_brace, "Expected '{' to start section body");

        // Parse section contents
        while (!self.check(.right_brace) and !self.isAtEnd()) {
            if (self.current.type == .newline or self.current.type == .comment) {
                try self.advance();
                continue;
            }

            const content = try self.parseSectionContent();
            if (content) |c| {
                try contents.append(c);
            }
        }

        try self.consume(.right_brace, "Expected '}' to end section body");

        // Parse optional attributes after closing brace
        while (true) {
            if (try self.match(.greater_than)) { // AT>region
                region = try self.consumeIdentifier("Expected region name");
            } else if (try self.matchKeyword("AT")) {
                try self.consume(.left_paren, "Expected '(' after AT");
                at_address = try self.parseExpression();
                try self.consume(.right_paren, "Expected ')' after AT expression");
            } else if (try self.matchKeyword("ALIGN")) {
                try self.consume(.left_paren, "Expected '(' after ALIGN");
                align_expr = try self.parseExpression();
                try self.consume(.right_paren, "Expected ')' after ALIGN expression");
            } else if (try self.matchKeyword("SUBALIGN")) {
                try self.consume(.left_paren, "Expected '(' after SUBALIGN");
                subalign_expr = try self.parseExpression();
                try self.consume(.right_paren, "Expected ')' after SUBALIGN expression");
            } else if (try self.matchKeyword("ONLY_IF_RO") or try self.matchKeyword("ONLY_IF_RW")) {
                // These are constraints - for simplicity, we'll just note them
                constraint = try self.allocator.create(Expression);
                constraint.?.* = .{ .identifier = self.previous.lexeme };
            } else if (self.check(.colon)) {
                try self.advance();
                // Parse program headers
                while (self.check(.identifier)) {
                    try phdr_list.append(self.current.lexeme);
                    try self.advance();
                }
            } else {
                break;
            }
        }

        return SectionDefinition{
            .name = name,
            .address = address,
            .type_info = type_info,
            .contents = contents,
            .at_address = at_address,
            .align_expr = align_expr,
            .subalign_expr = subalign_expr,
            .constraint = constraint,
            .fill_expr = fill_expr,
            .region = region,
            .lma_region = lma_region,
            .phdr_list = phdr_list,
        };
    }

    fn parseSectionContent(self: *Self) !?SectionContent {
        return switch (self.current.type) {
            .keep => {
                const keep_cmd = try self.parseKeepCommand();
                return SectionContent{ .keep_command = keep_cmd };
            },
            .sort, .sort_by_name, .sort_by_alignment, .sort_by_init_priority => {
                const sort_cmd = try self.parseSortCommand();
                return SectionContent{ .sort_command = sort_cmd };
            },
            .@"align" => {
                const align_cmd = try self.parseAlignCommand();
                return SectionContent{ .align_command = align_cmd };
            },
            .assert_kw => {
                const assert_cmd = try self.parseAssertCommand();
                return SectionContent{ .assert_command = assert_cmd };
            },
            .identifier => {
                if (self.peekAssignment()) {
                    const assignment = try self.parseAssignmentExpr();
                    return SectionContent{ .assignment = assignment };
                } else {
                    const input_section = try self.parseInputSection();
                    return SectionContent{ .input_section = input_section };
                }
            },
            .multiply => {
                // Fill expression
                const fill_expr = try self.parseExpression();
                return SectionContent{ .fill = fill_expr };
            },
            else => {
                try self.advance();
                return null;
            },
        };
    }

    fn parseKeepCommand(self: *Self) !KeepCommand {
        try self.consume(.keep, "Expected 'KEEP'");
        try self.consume(.left_paren, "Expected '(' after KEEP");

        var input_sections = ArrayList(InputSection).init(self.allocator);

        while (!self.check(.right_paren) and !self.isAtEnd()) {
            const input_section = try self.parseInputSection();
            try input_sections.append(input_section);
        }

        try self.consume(.right_paren, "Expected ')' after KEEP contents");
        _ = try self.consumeOptional(.semicolon);

        return KeepCommand{ .input_sections = input_sections };
    }

    fn parseSortCommand(self: *Self) !SortCommand {
        const sort_type: SortType = switch (self.current.type) {
            .sort => .none,
            .sort_by_name => .by_name,
            .sort_by_alignment => .by_alignment,
            .sort_by_init_priority => .by_init_priority,
            else => unreachable,
        };

        try self.advance(); // consume sort keyword
        try self.consume(.left_paren, "Expected '(' after SORT");

        var input_sections = ArrayList(InputSection).init(self.allocator);

        while (!self.check(.right_paren) and !self.isAtEnd()) {
            const input_section = try self.parseInputSection();
            try input_sections.append(input_section);
        }

        try self.consume(.right_paren, "Expected ')' after SORT contents");
        _ = try self.consumeOptional(.semicolon);

        return SortCommand{
            .sort_type = sort_type,
            .input_sections = input_sections,
        };
    }

    fn parseAlignCommand(self: *Self) !AlignCommand {
        try self.consume(.@"align", "Expected 'ALIGN'");
        try self.consume(.left_paren, "Expected '(' after ALIGN");

        const expr = try self.parseExpression();
        var fill: ?*Expression = null;

        if (try self.consumeOptional(.comma)) {
            fill = try self.parseExpression();
        }

        try self.consume(.right_paren, "Expected ')' after ALIGN expression");
        _ = try self.consumeOptional(.semicolon);

        return AlignCommand{
            .expr = expr,
            .fill = fill,
        };
    }

    fn parseAssertCommand(self: *Self) !AssertCommand {
        try self.consume(.assert_kw, "Expected 'ASSERT'");
        try self.consume(.left_paren, "Expected '(' after ASSERT");

        const condition = try self.parseExpression();
        var message: ?[]const u8 = null;

        if (try self.consumeOptional(.comma)) {
            message = try self.consumeString("Expected error message");
        }

        try self.consume(.right_paren, "Expected ')' after ASSERT");
        _ = try self.consumeOptional(.semicolon);

        return AssertCommand{
            .condition = condition,
            .message = message,
        };
    }

    fn parseInputSection(self: *Self) !InputSection {
        var file_spec: ?[]const u8 = null;
        var section_spec = ArrayList([]const u8).init(self.allocator);
        const exclude_files = ArrayList([]const u8).init(self.allocator);
        const sort_type: ?SortType = null;

        // Parse file specification
        if (self.check(.identifier) or self.check(.string)) {
            file_spec = self.current.lexeme;
            try self.advance();
        } else if (self.check(.multiply)) {
            try self.advance();
            file_spec = "*";
        }

        // Parse section specification in parentheses
        if (try self.consumeOptional(.left_paren)) {
            while (!self.check(.right_paren) and !self.isAtEnd()) {
                if (self.check(.identifier) or self.check(.string)) {
                    try section_spec.append(self.current.lexeme);
                    try self.advance();
                } else if (self.check(.multiply)) {
                    try self.advance();
                    try section_spec.append("*");
                } else {
                    try self.advance();
                }
                _ = try self.consumeOptional(.comma);
            }
            try self.consume(.right_paren, "Expected ')' after section specification");
        }

        _ = try self.consumeOptional(.semicolon);

        return InputSection{
            .file_spec = file_spec,
            .section_spec = section_spec,
            .exclude_files = exclude_files,
            .sort_type = sort_type,
        };
    }

    fn parseMemory(self: *Self) !*AstNode {
        const line = self.current.line;
        const column = self.current.column;

        try self.consume(.memory, "Expected 'MEMORY'");
        try self.consume(.left_brace, "Expected '{' after MEMORY");

        var regions = ArrayList(MemoryRegion).init(self.allocator);

        while (!self.check(.right_brace) and !self.isAtEnd()) {
            if (self.current.type == .newline or self.current.type == .comment) {
                try self.advance();
                continue;
            }

            const region = try self.parseMemoryRegion();
            try regions.append(region);
        }

        try self.consume(.right_brace, "Expected '}' after MEMORY regions");
        _ = try self.consumeOptional(.semicolon);

        const node = try self.allocator.create(AstNode);
        node.* = AstNode{
            .type = .memory_command,
            .data = .{ .memory = regions },
            .line = line,
            .column = column,
        };

        return node;
    }

    fn parseMemoryRegion(self: *Self) !MemoryRegion {
        const name = try self.consumeIdentifier("Expected memory region name");

        var attributes: []const u8 = "";
        if (try self.consumeOptional(.left_paren)) {
            if (self.check(.identifier)) {
                attributes = self.current.lexeme;
                try self.advance();
            }
            try self.consume(.right_paren, "Expected ')' after attributes");
        }

        try self.consume(.colon, "Expected ':' after region name");

        // Parse ORIGIN = expression
        try self.consume(.origin, "Expected 'ORIGIN'");
        try self.consume(.assign, "Expected '=' after ORIGIN");
        const origin = try self.parseExpression();
        try self.consume(.comma, "Expected ',' after ORIGIN");

        // Parse LENGTH = expression
        try self.consume(.length, "Expected 'LENGTH'");
        try self.consume(.assign, "Expected '=' after LENGTH");
        const length = try self.parseExpression();

        _ = try self.consumeOptional(.semicolon);

        return MemoryRegion{
            .name = name,
            .attributes = attributes,
            .origin = origin,
            .length = length,
        };
    }

    fn parsePhdrs(self: *Self) !*AstNode {
        const line = self.current.line;
        const column = self.current.column;

        try self.consume(.phdrs, "Expected 'PHDRS'");
        try self.consume(.left_brace, "Expected '{' after PHDRS");

        var headers = ArrayList(ProgramHeader).init(self.allocator);

        while (!self.check(.right_brace) and !self.isAtEnd()) {
            if (self.current.type == .newline or self.current.type == .comment) {
                try self.advance();
                continue;
            }

            const header = try self.parseProgramHeader();
            try headers.append(header);
        }

        try self.consume(.right_brace, "Expected '}' after program headers");
        _ = try self.consumeOptional(.semicolon);

        const node = try self.allocator.create(AstNode);
        node.* = AstNode{
            .type = .phdrs_command,
            .data = .{ .phdrs = headers },
            .line = line,
            .column = column,
        };

        return node;
    }

    fn parseProgramHeader(self: *Self) !ProgramHeader {
        const name = try self.consumeIdentifier("Expected program header name");
        try self.consume(.colon, "Expected ':' after header name");

        const type_expr = try self.parseExpression();

        var filehdr = false;
        var phdrs = false;
        var at_expr: ?*Expression = null;
        var flags_expr: ?*Expression = null;

        // Parse optional attributes
        while (true) {
            if (try self.matchKeyword("FILEHDR")) {
                filehdr = true;
            } else if (try self.matchKeyword("PHDRS")) {
                phdrs = true;
            } else if (try self.matchKeyword("AT")) {
                try self.consume(.left_paren, "Expected '(' after AT");
                at_expr = try self.parseExpression();
                try self.consume(.right_paren, "Expected ')' after AT expression");
            } else if (try self.matchKeyword("FLAGS")) {
                try self.consume(.left_paren, "Expected '(' after FLAGS");
                flags_expr = try self.parseExpression();
                try self.consume(.right_paren, "Expected ')' after FLAGS expression");
            } else {
                break;
            }
        }

        _ = try self.consumeOptional(.semicolon);

        return ProgramHeader{
            .name = name,
            .type_expr = type_expr,
            .filehdr = filehdr,
            .phdrs = phdrs,
            .at_expr = at_expr,
            .flags_expr = flags_expr,
        };
    }

    fn parseProvide(self: *Self) !*AstNode {
        const line = self.current.line;
        const column = self.current.column;
        const hidden = self.current.type == .provide_hidden;

        try self.advance(); // consume PROVIDE or PROVIDE_HIDDEN
        try self.consume(.left_paren, "Expected '(' after PROVIDE");

        var assignment = try self.parseAssignmentExpr();
        assignment.provide = true;
        assignment.hidden = hidden;

        try self.consume(.right_paren, "Expected ')' after PROVIDE assignment");
        _ = try self.consumeOptional(.semicolon);

        const node = try self.allocator.create(AstNode);
        node.* = AstNode{
            .type = .provide_command,
            .data = .{ .provide = assignment },
            .line = line,
            .column = column,
        };

        return node;
    }

    fn parseAssignment(self: *Self) !*AstNode {
        const line = self.current.line;
        const column = self.current.column;

        const assignment = try self.parseAssignmentExpr();

        const node = try self.allocator.create(AstNode);
        node.* = AstNode{
            .type = .assignment,
            .data = .{ .assignment = assignment },
            .line = line,
            .column = column,
        };

        return node;
    }

    fn parseAssignmentExpr(self: *Self) !Assignment {
        const target = try self.consumeIdentifier("Expected assignment target");

        const operator = self.current.type;
        if (!self.isAssignmentOperator(operator)) {
            return error.ExpectedAssignmentOperator;
        }
        try self.advance();

        const value = try self.parseExpression();
        _ = try self.consumeOptional(.semicolon);

        return Assignment{
            .target = target,
            .operator = operator,
            .value = value,
            .provide = false,
            .hidden = false,
        };
    }

    fn parseExpression(self: *Self) anyerror!*Expression {
        return self.parseTernary();
    }

    fn parseTernary(self: *Self) !*Expression {
        const expr = try self.parseLogicalOr();

        if (try self.consumeOptional(.question)) {
            const true_expr = try self.parseExpression();
            try self.consume(.colon, "Expected ':' after ternary true expression");
            const false_expr = try self.parseExpression();

            const ternary = try self.allocator.create(Expression);
            ternary.* = .{
                .ternary = .{
                    .condition = expr,
                    .true_expr = true_expr,
                    .false_expr = false_expr,
                },
            };
            return ternary;
        }

        return expr;
    }

    fn parseLogicalOr(self: *Self) !*Expression {
        var expr = try self.parseLogicalAnd();

        while (try self.consumeOptional(.logical_or)) {
            const operator = self.previous.type;
            const right = try self.parseLogicalAnd();
            const binary = try self.allocator.create(Expression);
            binary.* = .{
                .binary_op = .{
                    .left = expr,
                    .operator = operator,
                    .right = right,
                },
            };
            expr = binary;
        }

        return expr;
    }

    fn parseLogicalAnd(self: *Self) !*Expression {
        var expr = try self.parseBitwiseOr();

        while (try self.consumeOptional(.logical_and)) {
            const operator = self.previous.type;
            const right = try self.parseBitwiseOr();
            const binary = try self.allocator.create(Expression);
            binary.* = .{
                .binary_op = .{
                    .left = expr,
                    .operator = operator,
                    .right = right,
                },
            };
            expr = binary;
        }

        return expr;
    }

    fn parseBitwiseOr(self: *Self) !*Expression {
        var expr = try self.parseBitwiseXor();

        while (try self.consumeOptional(.bitwise_or)) {
            const operator = self.previous.type;
            const right = try self.parseBitwiseXor();
            const binary = try self.allocator.create(Expression);
            binary.* = .{
                .binary_op = .{
                    .left = expr,
                    .operator = operator,
                    .right = right,
                },
            };
            expr = binary;
        }

        return expr;
    }

    fn parseBitwiseXor(self: *Self) !*Expression {
        var expr = try self.parseBitwiseAnd();

        while (try self.consumeOptional(.bitwise_xor)) {
            const operator = self.previous.type;
            const right = try self.parseBitwiseAnd();
            const binary = try self.allocator.create(Expression);
            binary.* = .{
                .binary_op = .{
                    .left = expr,
                    .operator = operator,
                    .right = right,
                },
            };
            expr = binary;
        }

        return expr;
    }

    fn parseBitwiseAnd(self: *Self) !*Expression {
        var expr = try self.parseEquality();

        while (try self.consumeOptional(.bitwise_and)) {
            const operator = self.previous.type;
            const right = try self.parseEquality();
            const binary = try self.allocator.create(Expression);
            binary.* = .{
                .binary_op = .{
                    .left = expr,
                    .operator = operator,
                    .right = right,
                },
            };
            expr = binary;
        }

        return expr;
    }

    fn parseEquality(self: *Self) !*Expression {
        var expr = try self.parseComparison();

        while (self.current.type == .equal or self.current.type == .not_equal) {
            const operator = self.current.type;
            try self.advance();
            const right = try self.parseComparison();
            const binary = try self.allocator.create(Expression);
            binary.* = .{
                .binary_op = .{
                    .left = expr,
                    .operator = operator,
                    .right = right,
                },
            };
            expr = binary;
        }

        return expr;
    }

    fn parseComparison(self: *Self) !*Expression {
        var expr = try self.parseShift();

        while (self.current.type == .greater_than or self.current.type == .greater_equal or
            self.current.type == .less_than or self.current.type == .less_equal)
        {
            const operator = self.current.type;
            try self.advance();
            const right = try self.parseShift();
            const binary = try self.allocator.create(Expression);
            binary.* = .{
                .binary_op = .{
                    .left = expr,
                    .operator = operator,
                    .right = right,
                },
            };
            expr = binary;
        }

        return expr;
    }

    fn parseShift(self: *Self) !*Expression {
        var expr = try self.parseAddition();

        while (self.current.type == .left_shift or self.current.type == .right_shift) {
            const operator = self.current.type;
            try self.advance();
            const right = try self.parseAddition();
            const binary = try self.allocator.create(Expression);
            binary.* = .{
                .binary_op = .{
                    .left = expr,
                    .operator = operator,
                    .right = right,
                },
            };
            expr = binary;
        }

        return expr;
    }

    fn parseAddition(self: *Self) !*Expression {
        var expr = try self.parseMultiplication();

        while (self.current.type == .plus or self.current.type == .minus) {
            const operator = self.current.type;
            try self.advance();
            const right = try self.parseMultiplication();
            const binary = try self.allocator.create(Expression);
            binary.* = .{
                .binary_op = .{
                    .left = expr,
                    .operator = operator,
                    .right = right,
                },
            };
            expr = binary;
        }

        return expr;
    }

    fn parseMultiplication(self: *Self) !*Expression {
        var expr = try self.parseUnary();

        while (self.current.type == .multiply or self.current.type == .divide or self.current.type == .modulo) {
            const operator = self.current.type;
            try self.advance();
            const right = try self.parseUnary();
            const binary = try self.allocator.create(Expression);
            binary.* = .{
                .binary_op = .{
                    .left = expr,
                    .operator = operator,
                    .right = right,
                },
            };
            expr = binary;
        }

        return expr;
    }

    fn parseUnary(self: *Self) !*Expression {
        if (self.current.type == .logical_not or self.current.type == .bitwise_not or
            self.current.type == .minus or self.current.type == .plus)
        {
            const operator = self.current.type;
            try self.advance();
            const operand = try self.parseUnary();
            const unary = try self.allocator.create(Expression);
            unary.* = .{
                .unary_op = .{
                    .operator = operator,
                    .operand = operand,
                },
            };
            return unary;
        }

        return self.parsePrimary();
    }

    fn parsePrimary(self: *Self) !*Expression {
        switch (self.current.type) {
            .number => {
                const value = try self.parseNumber();
                try self.advance();
                const expr = try self.allocator.create(Expression);
                expr.* = .{ .number = value };
                return expr;
            },
            .string => {
                const value = self.current.lexeme;
                try self.advance();
                const expr = try self.allocator.create(Expression);
                expr.* = .{ .string = value };
                return expr;
            },
            .identifier => {
                const name = self.current.lexeme;
                try self.advance();

                // Check for function call
                if (try self.consumeOptional(.left_paren)) {
                    var args = ArrayList(*Expression).init(self.allocator);

                    while (!self.check(.right_paren) and !self.isAtEnd()) {
                        const arg = try self.parseExpression();
                        try args.append(arg);
                        _ = try self.consumeOptional(.comma);
                    }

                    try self.consume(.right_paren, "Expected ')' after function arguments");

                    const expr = try self.allocator.create(Expression);
                    expr.* = .{
                        .function_call = .{
                            .name = name,
                            .args = args,
                        },
                    };
                    return expr;
                }

                const expr = try self.allocator.create(Expression);
                expr.* = .{ .identifier = name };
                return expr;
            },
            .dot => {
                try self.advance();
                const expr = try self.allocator.create(Expression);
                expr.* = .location_counter;
                return expr;
            },
            .left_paren => {
                try self.advance();
                const expr = try self.parseExpression();
                try self.consume(.right_paren, "Expected ')' after expression");
                return expr;
            },
            else => |tag| {
                std.debug.print("Unexpected token '{s}' at line {}, column {}\n", .{ @tagName(tag), self.lexer.line, self.lexer.column });
                return error.UnexpectedToken;
            },
        }
    }

    fn parseNumber(self: *Self) !u64 {
        const lexeme = self.current.lexeme;

        // Handle different number formats
        if (lexeme.len > 2 and lexeme[0] == '0' and (lexeme[1] == 'x' or lexeme[1] == 'X')) {
            // Hexadecimal
            return std.fmt.parseInt(u64, lexeme[2..], 16);
        } else if (lexeme.len > 1 and lexeme[0] == '0' and std.ascii.isDigit(lexeme[1])) {
            // Octal
            return std.fmt.parseInt(u64, lexeme, 8);
        } else {
            // Decimal, possibly with suffix
            var num_part = lexeme;
            var multiplier: u64 = 1;

            if (lexeme.len > 0) {
                const last_char = lexeme[lexeme.len - 1];
                if (last_char == 'K' or last_char == 'k') {
                    multiplier = 1024;
                    num_part = lexeme[0 .. lexeme.len - 1];
                } else if (last_char == 'M' or last_char == 'm') {
                    multiplier = 1024 * 1024;
                    num_part = lexeme[0 .. lexeme.len - 1];
                } else if (last_char == 'G' or last_char == 'g') {
                    multiplier = 1024 * 1024 * 1024;
                    num_part = lexeme[0 .. lexeme.len - 1];
                }
            }

            const base_value = try std.fmt.parseInt(u64, num_part, 10);
            return base_value * multiplier;
        }
    }

    // Helper methods
    fn advance(self: *Self) !void {
        if (!self.isAtEnd()) {
            self.previous = self.current;
            self.current = try self.lexer.scanToken();
        }
    }

    fn isAtEnd(self: *Self) bool {
        return self.current.type == .eof;
    }

    fn check(self: *Self, token_type: TokenType) bool {
        if (self.isAtEnd()) return false;
        return self.current.type == token_type;
    }

    fn match(self: *Self, token_type: TokenType) !bool {
        if (!self.check(token_type)) return false;
        try self.advance();
        return true;
    }

    fn matchKeyword(self: *Self, keyword: []const u8) !bool {
        if (!self.check(.identifier)) return false;
        if (!std.mem.eql(u8, self.current.lexeme, keyword)) return false;
        try self.advance();
        return true;
    }

    fn consume(self: *Self, token_type: TokenType, message: []const u8) !void {
        if (self.current.type == token_type) {
            try self.advance();
            return;
        }

        std.debug.print("Parse error at line {d}, column {d}: {s}\n", .{ self.current.line, self.current.column, message });
        return error.ParseError;
    }

    fn consumeOptional(self: *Self, token_type: TokenType) !bool {
        if (self.check(token_type)) {
            try self.advance();
            return true;
        }
        return false;
    }

    fn consumeIdentifier(self: *Self, message: []const u8) ![]const u8 {
        if (self.current.type == .identifier) {
            const lexeme = self.current.lexeme;
            try self.advance();
            return lexeme;
        }

        std.debug.print("Parse error at line {d}, column {d}: {s}\n", .{ self.current.line, self.current.column, message });
        return error.ParseError;
    }

    fn consumeString(self: *Self, message: []const u8) ![]const u8 {
        if (self.current.type == .string) {
            const lexeme = self.current.lexeme;
            try self.advance();
            // Remove quotes from string literal
            if (lexeme.len >= 2 and lexeme[0] == '"' and lexeme[lexeme.len - 1] == '"') {
                return lexeme[1 .. lexeme.len - 1];
            }
            return lexeme;
        }

        std.debug.print("Parse error at line {d}, column {d}: {s}\n", .{ self.current.line, self.current.column, message });
        return error.ParseError;
    }

    fn peekAssignment(self: *Self) bool {
        // Simple lookahead to check if this is an assignment
        // In a production parser, you'd want more sophisticated lookahead
        const saved_current = self.current;
        const saved_previous = self.previous;
        const saved_position = self.lexer.current;
        const saved_line = self.lexer.line;
        const saved_column = self.lexer.column;

        defer {
            self.current = saved_current;
            self.previous = saved_previous;
            self.lexer.current = saved_position;
            self.lexer.line = saved_line;
            self.lexer.column = saved_column;
        }

        // Skip identifier
        if (self.current.type == .identifier) {
            _ = self.advance() catch return false;
            return self.isAssignmentOperator(self.current.type);
        }

        return false;
    }

    fn isAssignmentOperator(self: *Self, token_type: TokenType) bool {
        _ = self;

        return switch (token_type) {
            .assign, .add_assign, .sub_assign, .mul_assign, .div_assign, .lshift_assign, .rshift_assign, .and_assign, .or_assign => true,
            else => false,
        };
    }
};

// AST visitor for traversing and processing the parsed tree
pub const AstVisitor = struct {
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{ .allocator = allocator };
    }

    pub fn visit(self: *Self, node: *AstNode) void {
        switch (node.type) {
            .script => {
                for (node.data.script.items) |child| {
                    self.visit(child);
                }
            },
            .entry_command => {
                std.debug.print("Entry point: {s}\n", .{node.data.entry});
            },
            .include_command => {
                std.debug.print("Include: {s}\n", .{node.data.include});
            },
            .input_command => {
                std.debug.print("Input files:\n", .{});
                for (node.data.input.items) |file| {
                    std.debug.print("  - {s}\n", .{file});
                }
            },
            .sections_command => {
                std.debug.print("Sections:\n", .{});
                for (node.data.sections.items) |section| {
                    self.visitSection(&section);
                }
            },
            .memory_command => {
                std.debug.print("Memory regions:\n", .{});
                for (node.data.memory.items) |region| {
                    self.visitMemoryRegion(&region);
                }
            },
            .assignment => {
                self.visitAssignment(&node.data.assignment);
            },
            else => {
                std.debug.print("Unhandled node type: {}\n", .{node.type});
            },
        }
    }

    fn visitSection(self: *Self, section: *const SectionDefinition) void {
        std.debug.print("  Section: {s}\n", .{section.name});
        if (section.address) |addr| {
            std.debug.print("    Address: ", .{});
            self.visitExpression(addr);
            std.debug.print("\n", .{});
        }

        for (section.contents.items) |content| {
            self.visitSectionContent(&content);
        }
    }

    fn visitSectionContent(self: *Self, content: *const SectionContent) void {
        switch (content.*) {
            .assignment => |assignment| {
                std.debug.print("    Assignment: ", .{});
                self.visitAssignment(&assignment);
            },
            .input_section => |input_section| {
                std.debug.print("    Input section:\n", .{});
                if (input_section.file_spec) |file| {
                    std.debug.print("      File: {s}\n", .{file});
                }
                for (input_section.section_spec.items) |section_name| {
                    std.debug.print("      Section: {s}\n", .{section_name});
                }
            },
            .keep_command => |keep_cmd| {
                std.debug.print("    KEEP command with {} input sections\n", .{keep_cmd.input_sections.items.len});
            },
            .align_command => |align_cmd| {
                std.debug.print("    ALIGN: ", .{});
                self.visitExpression(align_cmd.expr);
                std.debug.print("\n", .{});
            },
            .assert_command => |assert_cmd| {
                std.debug.print("    ASSERT: ", .{});
                self.visitExpression(assert_cmd.condition);
                if (assert_cmd.message) |msg| {
                    std.debug.print(" \"{s}\"", .{msg});
                }
                std.debug.print("\n", .{});
            },
            else => {
                std.debug.print("    Unhandled section content\n", .{});
            },
        }
    }

    fn visitMemoryRegion(self: *Self, region: *const MemoryRegion) void {
        std.debug.print("  Region: {s} ({s})\n", .{ region.name, region.attributes });
        std.debug.print("    Origin: ", .{});
        self.visitExpression(region.origin);
        std.debug.print("\n    Length: ", .{});
        self.visitExpression(region.length);
        std.debug.print("\n", .{});
    }

    fn visitAssignment(self: *Self, assignment: *const Assignment) void {
        std.debug.print("{s} {} ", .{ assignment.target, assignment.operator });
        self.visitExpression(assignment.value);
        std.debug.print("\n", .{});
    }

    fn visitExpression(self: *Self, expr: *const Expression) void {
        switch (expr.*) {
            .binary_op => |binary| {
                std.debug.print("(", .{});
                self.visitExpression(binary.left);
                std.debug.print(" {} ", .{binary.operator});
                self.visitExpression(binary.right);
                std.debug.print(")", .{});
            },
            .unary_op => |unary| {
                std.debug.print("({}", .{unary.operator});
                self.visitExpression(unary.operand);
                std.debug.print(")", .{});
            },
            .ternary => |ternary| {
                std.debug.print("(", .{});
                self.visitExpression(ternary.condition);
                std.debug.print(" ? ", .{});
                self.visitExpression(ternary.true_expr);
                std.debug.print(" : ", .{});
                self.visitExpression(ternary.false_expr);
                std.debug.print(")", .{});
            },
            .function_call => |func| {
                std.debug.print("{s}(", .{func.name});
                for (func.args.items, 0..) |arg, i| {
                    if (i > 0) std.debug.print(", ", .{});
                    self.visitExpression(arg);
                }
                std.debug.print(")", .{});
            },
            .identifier => |id| {
                std.debug.print("{s}", .{id});
            },
            .number => |num| {
                std.debug.print("{d}", .{num});
            },
            .string => |str| {
                std.debug.print("\"{s}\"", .{str});
            },
            .location_counter => {
                std.debug.print(".", .{});
            },
        }
    }
};

// Main parser interface
pub const LinkerScriptParser = struct {
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{ .allocator = allocator };
    }

    pub fn parseScript(self: *Self, input: []const u8) !*AstNode {
        var lexer = try Lexer.init(self.allocator, input);
        defer lexer.deinit();

        var parser = try Parser.init(self.allocator, &lexer);
        return parser.parse();
    }

    pub fn parseFile(self: *Self, file_path: []const u8) !*AstNode {
        const file = try std.fs.cwd().openFile(file_path, .{});
        defer file.close();

        const file_size = try file.getEndPos();
        const contents = try self.allocator.alloc(u8, file_size);
        defer self.allocator.free(contents);

        _ = try file.readAll(contents);
        return self.parseScript(contents);
    }

    pub fn printAst(self: *Self, ast: *AstNode) void {
        var visitor = AstVisitor.init(self.allocator);
        visitor.visit(ast);
    }

    pub fn freeAst(self: *Self, ast: *AstNode) void {
        self.freeAstRecursive(ast);
    }

    fn freeAstRecursive(self: *Self, node: *AstNode) void {
        switch (node.type) {
            .script => {
                for (node.data.script.items) |child| {
                    self.freeAstRecursive(child);
                }
                node.data.script.deinit();
            },
            .sections_command => {
                for (node.data.sections.items) |*section| {
                    self.freeSectionDefinition(section);
                }
                node.data.sections.deinit();
            },
            .memory_command => {
                for (node.data.memory.items) |*region| {
                    self.freeMemoryRegion(region);
                }
                node.data.memory.deinit();
            },
            .input_command => {
                node.data.input.deinit();
            },
            .group_command => {
                node.data.group.deinit();
            },
            .assignment => {
                self.freeExpression(node.data.assignment.value);
            },
            .provide => {
                self.freeExpression(node.data.provide.value);
            },
            else => {},
        }

        self.allocator.destroy(node);
    }

    fn freeSectionDefinition(self: *Self, section: *SectionDefinition) void {
        if (section.address) |addr| {
            self.freeExpression(addr);
        }
        if (section.at_address) |addr| {
            self.freeExpression(addr);
        }
        if (section.align_expr) |expr| {
            self.freeExpression(expr);
        }
        if (section.subalign_expr) |expr| {
            self.freeExpression(expr);
        }
        if (section.constraint) |expr| {
            self.freeExpression(expr);
        }
        if (section.fill_expr) |expr| {
            self.freeExpression(expr);
        }

        for (section.contents.items) |*content| {
            self.freeSectionContent(content);
        }
        section.contents.deinit();
        section.phdr_list.deinit();
    }

    fn freeSectionContent(self: *Self, content: *SectionContent) void {
        switch (content.*) {
            .assignment => |*assignment| {
                self.freeExpression(assignment.value);
            },
            .input_section => |*input_section| {
                input_section.section_spec.deinit();
                input_section.exclude_files.deinit();
            },
            .keep_command => |*keep_cmd| {
                for (keep_cmd.input_sections.items) |*input_section| {
                    input_section.section_spec.deinit();
                    input_section.exclude_files.deinit();
                }
                keep_cmd.input_sections.deinit();
            },
            .sort_command => |*sort_cmd| {
                for (sort_cmd.input_sections.items) |*input_section| {
                    input_section.section_spec.deinit();
                    input_section.exclude_files.deinit();
                }
                sort_cmd.input_sections.deinit();
            },
            .align_command => |*align_cmd| {
                self.freeExpression(align_cmd.expr);
                if (align_cmd.fill) |fill| {
                    self.freeExpression(fill);
                }
            },
            .assert_command => |*assert_cmd| {
                self.freeExpression(assert_cmd.condition);
            },
            .fill => |expr| {
                self.freeExpression(expr);
            },
            else => {},
        }
    }

    fn freeMemoryRegion(self: *Self, region: *MemoryRegion) void {
        self.freeExpression(region.origin);
        self.freeExpression(region.length);
    }

    fn freeExpression(self: *Self, expr: *Expression) void {
        switch (expr.*) {
            .binary_op => |*binary| {
                self.freeExpression(binary.left);
                self.freeExpression(binary.right);
            },
            .unary_op => |*unary| {
                self.freeExpression(unary.operand);
            },
            .ternary => |*ternary| {
                self.freeExpression(ternary.condition);
                self.freeExpression(ternary.true_expr);
                self.freeExpression(ternary.false_expr);
            },
            .function_call => |*func| {
                for (func.args.items) |arg| {
                    self.freeExpression(arg);
                }
                func.args.deinit();
            },
            else => {},
        }

        self.allocator.destroy(expr);
    }
};

// Example usage and test functions
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Example linker script
    const example_script =
        \\ENTRY(_start)
        \\
        \\MEMORY
        \\{
        \\  rom (rx)  : ORIGIN = 0x08000000, LENGTH = 256K
        \\  ram (rwx) : ORIGIN = 0x20000000, LENGTH = 64K
        \\}
        \\
        \\SECTIONS
        \\{
        \\  .text : {
        \\    *(.text*)
        \\    *(.rodata*)
        \\  } > rom
        \\
        \\  .data : {
        \\    _data_start = .;
        \\    *(.data*)
        \\    _data_end = .;
        \\  } > ram AT > rom
        \\
        \\  .bss : {
        \\    _bss_start = .;
        \\    *(.bss*)
        \\    _bss_end = .;
        \\  } > ram
        \\
        \\  /DISCARD/ : {
        \\    *(.ARM.exidx*)
        \\  }
        \\}
    ;

    var parser = LinkerScriptParser.init(allocator);

    std.debug.print("Parsing example linker script...\n", .{});
    const ast = parser.parseScript(example_script) catch |err| {
        std.debug.print("Parse error: {}\n", .{err});
        return;
    };

    std.debug.print("\nAST structure:\n", .{});
    parser.printAst(ast);

    // Clean up
    parser.freeAst(ast);

    std.debug.print("\nParsing completed successfully!\n", .{});
}

// Tests
test "lexer basic tokens" {
    const allocator = std.testing.allocator;

    var lexer = try Lexer.init(allocator, "ENTRY ( _start ) ;");
    defer lexer.deinit();

    const tokens = [_]TokenType{ .entry, .left_paren, .identifier, .right_paren, .semicolon, .eof };

    for (tokens) |expected| {
        const token = try lexer.scanToken();
        try std.testing.expect(token.type == expected);
    }
}

test "lexer numbers" {
    const allocator = std.testing.allocator;

    var lexer = try Lexer.init(allocator, "123 0x1000 0755 1K 2M");
    defer lexer.deinit();

    for (0..5) |_| {
        const token = try lexer.scanToken();
        try std.testing.expect(token.type == .number);
    }
}

test "parser simple entry" {
    const allocator = std.testing.allocator;

    const script = "ENTRY(_start);";
    var parser_instance = LinkerScriptParser.init(allocator);

    const ast = try parser_instance.parseScript(script);
    defer parser_instance.freeAst(ast);

    try std.testing.expect(ast.type == .script);
    try std.testing.expect(ast.data.script.items.len == 1);
    try std.testing.expect(ast.data.script.items[0].type == .entry_command);
}

test "parser memory section" {
    const allocator = std.testing.allocator;

    const script =
        \\MEMORY {
        \\  rom : ORIGIN = 0x1000, LENGTH = 64K
        \\}
    ;

    var parser_instance = LinkerScriptParser.init(allocator);

    const ast = try parser_instance.parseScript(script);
    defer parser_instance.freeAst(ast);

    try std.testing.expect(ast.type == .script);
    try std.testing.expect(ast.data.script.items.len == 1);
    try std.testing.expect(ast.data.script.items[0].type == .memory_command);
}
