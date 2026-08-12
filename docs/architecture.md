# LSMF Architecture

## Overview

The Linux Security Management Framework (LSMF) is built with a modular, extensible architecture designed for reliability, maintainability, and security.

The PySide6/Qt desktop application is the only graphical interface. It remains
unprivileged and delegates no host mutation until the typed privileged-helper
boundary passes its disposable-VM gates.

## Component Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Main Launcher (lsmf)                    │
│  - CLI argument parsing                                     │
│  - Command routing                                          │
│  - Interactive UI coordination                              │
└────────────────┬────────────────────────────────────────────┘
                 │
     ┌───────────┴───────────┐
     │                       │
┌────▼─────┐          ┌─────▼────┐
│ Core Lib │          │ UI Layer │
│          │          │          │
│ common   │          │ menu.sh  │
│ backup   │          │          │
│ detection│          └──────────┘
│ reporting│
└────┬─────┘
     │
     │
┌────▼──────────────────────────────────────┐
│         Hardening Modules                 │
│                                           │
│  ssh_hardening                            │
│  firewall_hardening                       │
│  network_hardening                        │
│  kernel_hardening                         │
│  ...                                      │
└───────────────────────────────────────────┘
```

## Data Flow

1. **Initialization**
   - Load configuration
   - Source libraries
   - Initialize logging
   - Create run ID and directories

2. **Detection Phase**
   - Detect OS and distribution
   - Detect system role
   - Detect installed software
   - Save detection results

3. **Execution Phase**
   - Load selected modules
   - Backup configurations
   - Apply hardening
   - Validate changes
   - Log actions

4. **Reporting Phase**
   - Calculate security score
   - Generate reports (TXT, JSON, HTML)
   - Save to report directory

## Module System

### Module Lifecycle

```
┌──────────────┐
│  Load Module │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  Check State │ ◄─── Idempotent check
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Backup Files │ ◄─── Safety
└──────┬───────┘
       │
       ▼
┌──────────────┐
│Apply Changes │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│   Validate   │ ─── Fail ──► Rollback
└──────┬───────┘
       │
       ▼ Success
┌──────────────┐
│    Report    │
└──────────────┘
```

### Module Interface

Every module must implement:

- `run_<module>()` - Main execution
- `rollback_<module>()` - Undo changes
- `verify_<module>()` - Verify state

## Library Components

### common.sh
- Logging functions
- Command execution
- Validation helpers
- Utility functions
- Configuration reading

### backup.sh
- File backup/restore
- Rollback point creation
- Backup management
- Checksum verification

### detection.sh
- OS detection
- System role classification
- Software detection
- Hardware detection

### reporting.sh
- Security score calculation
- Report generation
- Multi-format output
- Data collection

## Security Design

### Defense in Depth

1. **Validation Layer**
   - Input validation
   - Configuration validation
   - Pre-execution checks

2. **Backup Layer**
   - Automatic backups
   - Metadata storage
   - Integrity verification

3. **Execution Layer**
   - Error handling
   - Transaction-like operations
   - Atomic changes where possible

4. **Verification Layer**
   - Post-execution validation
   - Service health checks
   - Automatic rollback on failure

### Safe Defaults

- Default deny firewall rules
- Secure SSH configuration
- Kernel hardening enabled
- Minimal services

## Extension Points

### Adding New Modules

1. Create module file in `src/modules/`
2. Implement required functions
3. Use library functions
4. Add to configuration
5. Test thoroughly

### Custom Profiles

1. Create profile in `config/profiles/`
2. Define module selection
3. Configure settings
4. Apply with `-p` flag

## Performance Considerations

- Sequential module execution (future: parallel where safe)
- Minimal redundant detection
- Efficient file operations
- Cached results where appropriate

## Future Architecture

### Planned Enhancements

- Plugin system for third-party modules
- Event-driven architecture
- Async execution where safe
- Database backend for state
- Native Qt signals and bounded local refresh where useful
