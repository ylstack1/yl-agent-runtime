# Threat Model

See PRD section 8.1 for the full threat model.

Threats to address:
- Workspace path escape
- Symlink/junction/reparse-point escape
- UNC and device path abuse
- Alternate data stream abuse (Windows)
- Environment variable and executable search-path hijacking
- Credential theft
- Process-tree escape and orphaned processes
- Resource exhaustion and fork bombs
- Unauthorized network access and exfiltration
- Remote impersonation and replay
- Approval spoofing and confused-deputy behavior
- Audit log tampering