# Agent Guidelines for zecrecy

## Build Commands
- `zig build` - Build the project (default: install step)
- `zig build test` - Run all tests (both module and executable tests)
- `zig build --help` - Show all available build options and steps

## Code Style
- **Language**: Zig 0.14.1 (minimum version from build.zig.zon)
- **Imports**: Use `const std = @import("std");` for standard library, `const mem = std.mem;` for common modules
- **Naming**: snake_case for variables, PascalCase for types, camelCase for functions
- **Comments**: Use `//!` for module-level docs, `//` for regular comments
- **Memory**: Always defer cleanup (e.g., `defer secret.deinit()`) and use `secureZero` for sensitive data
- **Error handling**: Use `try` for error propagation, `!` for error union types
- **Testing**: Use `std.testing.expect()`, `std.testing.expectEqual()`, and `std.testing.expectEqualSlices()`
- **Formatting**: Follow Zig's built-in formatter conventions

## Project Structure
- `src/main.zig` - Executable entry point (currently commented out)
- `src/root.zig` - Library module root (public API exports)
- `src/secret.zig` - Core secret and memory management functionality
- `build.zig` - Build configuration and steps
- Module name: "zecrecy" (import with `@import("zecrecy")`)

## Testing
- Run all tests: `zig build test` (runs tests in parallel)
- Run specific tests: `zig test src/secret.zig` (runs just the tests for `src/secret.zig`)
- Test files: Tests are embedded in source files using `test` blocks

## Version Control
- This project uses `jj` for version control.
- Check status: `jj st`
- Check log: `jj log`
- Change current commit message: `jj describe -m "MESSAGE"` (where MESSAGE is the commit message)
