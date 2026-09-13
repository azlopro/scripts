# Security and audit notes

This bundle is a technical hardening aid. It is not an ISO/IEC 27001
certification, a complete ISMS, or a claim of CIS Benchmark conformance.

The generated evidence supports review of these control areas without
reproducing the copyrighted ISO control text:

- asset and configuration inventory;
- identity, privileged access, and multifactor authentication;
- network segregation and restricted administrative access;
- secure configuration and reduction of exposed services;
- vulnerability remediation and automatic security updates;
- event logging, clock synchronization, and administrative audit trails;
- file-integrity monitoring;
- configuration backup, rollback, validation, and change evidence.

Organizational work still required includes an approved scope, risk register,
Statement of Applicability, policies, owners, training, supplier review,
incident response, backup/restore testing, business continuity, internal audit,
management review, corrective actions, and an independent certification audit.

Known decisions/exceptions for this host should be recorded separately:

- whether unencrypted root storage is accepted;
- whether membership in the root-equivalent `lxd` group is required;
- which application ports and services are approved;
- where logs and backups are stored off-host;
- patch/reboot maintenance window and responsible owner;
- TOTP recovery-code custody and emergency console procedure.

Both `fwknop` and `libpam-google-authenticator` are supplied by Ubuntu's
community-supported `universe` component. Their package provenance, update
status, and continued suitability should therefore be included in periodic
dependency review. The fwknop AppArmor profile is installed as an additional
confinement layer.
