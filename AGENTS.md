# Agent Guidelines for zecrecy

## Build Commands
- `zig build` - Build the project (default: install step)
- `zig build run` - Build and run the executable
- `zig build test` - Run all tests (both module and executable tests)
- `zig build --help` - Show all available build options and steps

## Code Style
- **Language**: Zig 0.15.0-dev.1092+d772c0627 (minimum version)
- **Imports**: Use `const std = @import("std");` for standard library
- **Naming**: snake_case for functions and variables, PascalCase for types
- **Comments**: Use `//!` for module-level docs, `//` for regular comments
- **Memory**: Always defer cleanup (e.g., `defer list.deinit()`)
- **Error handling**: Use `try` for error propagation, `!` for error union types
- **Testing**: Use `std.testing.expect()` and `std.testing.expectEqual()`
- **Formatting**: Follow Zig's built-in formatter conventions

## Project Structure
- `src/main.zig` - Executable entry point with main() function
- `src/root.zig` - Library module root (public API)
- `build.zig` - Build configuration and steps
- Module name: "zecrecy" (import with `@import("zecrecy")`)

## Testing
- Run single test: Use `zig build test` (runs all tests in parallel)
- Test files: Tests are embedded in source files using `test` blocks
- Fuzz testing: Available with `--fuzz` flag