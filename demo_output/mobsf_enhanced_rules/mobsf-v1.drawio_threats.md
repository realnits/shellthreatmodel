# mobsf-v1.drawio Threat Model

| Component | Threat | STRIDE | DREAD Avg | Risk Level | Mitigation |
|-----------|--------|--------|-----------|------------|------------|
| Shared Service (Backup) - Prod | Lack of repudiation evidence for security-relevant actions | Repudiation | 6.0 | Medium | Introduce tamper-proof logging with correlation IDs, user attribution, and retention policies. |
| Shared Service (Backup) - Prod | Broken authentication allowing unauthorized API access | Spoofing | 9.0 | High | Implement OAuth 2.0/OIDC, JWT validation, API key rotation, and rate limiting per identity. |
| Shared Service (Backup) - Prod | Denial of service through resource exhaustion | Denial of Service | 6.2 | Medium | Apply rate limiting, request size limits, connection pooling, and circuit breakers. |
| Shared Service (Storage) - Prod | Lack of repudiation evidence for security-relevant actions | Repudiation | 6.4 | Medium | Introduce tamper-proof logging with correlation IDs, user attribution, and retention policies. |
| Shared Service (Storage) - Prod | Broken authentication allowing unauthorized API access | Spoofing | 9.2 | High | Implement OAuth 2.0/OIDC, JWT validation, API key rotation, and rate limiting per identity. |
| Shared Service (Storage) - Prod | Denial of service through resource exhaustion | Denial of Service | 6.6 | Medium | Apply rate limiting, request size limits, connection pooling, and circuit breakers. |
| Shared Service (Backup) - Non-Prod | Lack of repudiation evidence for security-relevant actions | Repudiation | 6.0 | Medium | Introduce tamper-proof logging with correlation IDs, user attribution, and retention policies. |
| Shared Service (Backup) - Non-Prod | Broken authentication allowing unauthorized API access | Spoofing | 9.0 | High | Implement OAuth 2.0/OIDC, JWT validation, API key rotation, and rate limiting per identity. |
| Shared Service (Backup) - Non-Prod | Denial of service through resource exhaustion | Denial of Service | 6.2 | Medium | Apply rate limiting, request size limits, connection pooling, and circuit breakers. |
| Shared Service (Storage) - Non-Prod | Lack of repudiation evidence for security-relevant actions | Repudiation | 6.4 | Medium | Introduce tamper-proof logging with correlation IDs, user attribution, and retention policies. |
| Shared Service (Storage) - Non-Prod | Broken authentication allowing unauthorized API access | Spoofing | 9.2 | High | Implement OAuth 2.0/OIDC, JWT validation, API key rotation, and rate limiting per identity. |
| Shared Service (Storage) - Non-Prod | Denial of service through resource exhaustion | Denial of Service | 6.6 | Medium | Apply rate limiting, request size limits, connection pooling, and circuit breakers. |
| Shared Service (DR) - Prod | Lack of repudiation evidence for security-relevant actions | Repudiation | 6.0 | Medium | Introduce tamper-proof logging with correlation IDs, user attribution, and retention policies. |
| Shared Service (DR) - Prod | Broken authentication allowing unauthorized API access | Spoofing | 9.0 | High | Implement OAuth 2.0/OIDC, JWT validation, API key rotation, and rate limiting per identity. |
| Shared Service (DR) - Prod | Denial of service through resource exhaustion | Denial of Service | 6.2 | Medium | Apply rate limiting, request size limits, connection pooling, and circuit breakers. |
| Component Pe-6Z7vc4aFHUBcSmwPr-53->Component CC8SS4oqa_s0rqLthlYS-36 | Unauthenticated cross-boundary communication allowing spoofing | Spoofing | 6.4 | Medium | Add mutual TLS (mTLS), service mesh authentication, and network segmentation policies. |
| Component Pe-6Z7vc4aFHUBcSmwPr-53->Component CC8SS4oqa_s0rqLthlYS-36 | Insufficient network segmentation allowing lateral movement | Elevation of Privilege | 9.0 | High | Implement zero-trust networking, microsegmentation, and least-privilege firewall rules. |
| Component Pe-6Z7vc4aFHUBcSmwPr-53->Component CC8SS4oqa_s0rqLthlYS-36 | Unauthenticated cross-boundary communication allowing spoofing | Spoofing | 6.4 | Medium | Add mutual TLS (mTLS), service mesh authentication, and network segmentation policies. |
| Component Pe-6Z7vc4aFHUBcSmwPr-53->Component CC8SS4oqa_s0rqLthlYS-36 | Insufficient network segmentation allowing lateral movement | Elevation of Privilege | 9.0 | High | Implement zero-trust networking, microsegmentation, and least-privilege firewall rules. |
| Transit Gateway->Component Pe-6Z7vc4aFHUBcSmwPr-53 | Unauthenticated cross-boundary communication allowing spoofing | Spoofing | 6.4 | Medium | Add mutual TLS (mTLS), service mesh authentication, and network segmentation policies. |
| Transit Gateway->Component Pe-6Z7vc4aFHUBcSmwPr-53 | Insufficient network segmentation allowing lateral movement | Elevation of Privilege | 9.0 | High | Implement zero-trust networking, microsegmentation, and least-privilege firewall rules. |
| Transit Gateway->Component Pe-6Z7vc4aFHUBcSmwPr-53 | Unauthenticated cross-boundary communication allowing spoofing | Spoofing | 6.4 | Medium | Add mutual TLS (mTLS), service mesh authentication, and network segmentation policies. |
| Transit Gateway->Component Pe-6Z7vc4aFHUBcSmwPr-53 | Insufficient network segmentation allowing lateral movement | Elevation of Privilege | 9.0 | High | Implement zero-trust networking, microsegmentation, and least-privilege firewall rules. |
| Component CC8SS4oqa_s0rqLthlYS-36->Component Pe-6Z7vc4aFHUBcSmwPr-66 | Unauthenticated cross-boundary communication allowing spoofing | Spoofing | 6.4 | Medium | Add mutual TLS (mTLS), service mesh authentication, and network segmentation policies. |
| Component CC8SS4oqa_s0rqLthlYS-36->Component Pe-6Z7vc4aFHUBcSmwPr-66 | Insufficient network segmentation allowing lateral movement | Elevation of Privilege | 9.0 | High | Implement zero-trust networking, microsegmentation, and least-privilege firewall rules. |
| Component CC8SS4oqa_s0rqLthlYS-36->Component 0kTWfv4hnWPTGup1sJnH-3 | Unauthenticated cross-boundary communication allowing spoofing | Spoofing | 6.4 | Medium | Add mutual TLS (mTLS), service mesh authentication, and network segmentation policies. |
| Component CC8SS4oqa_s0rqLthlYS-36->Component 0kTWfv4hnWPTGup1sJnH-3 | Insufficient network segmentation allowing lateral movement | Elevation of Privilege | 9.0 | High | Implement zero-trust networking, microsegmentation, and least-privilege firewall rules. |
| Component CC8SS4oqa_s0rqLthlYS-36->Component 0kTWfv4hnWPTGup1sJnH-2 | Unauthenticated cross-boundary communication allowing spoofing | Spoofing | 6.4 | Medium | Add mutual TLS (mTLS), service mesh authentication, and network segmentation policies. |
| Component CC8SS4oqa_s0rqLthlYS-36->Component 0kTWfv4hnWPTGup1sJnH-2 | Insufficient network segmentation allowing lateral movement | Elevation of Privilege | 9.0 | High | Implement zero-trust networking, microsegmentation, and least-privilege firewall rules. |
| KMS | Cryptographic key exposure through inadequate protection | Information Disclosure | 8.8 | High | Use hardware security modules (HSM), key rotation policies, and envelope encryption. |
| KMS | Weak key derivation functions allowing brute-force attacks | Spoofing | 6.4 | Medium | Use PBKDF2, bcrypt, or Argon2 with high work factors; avoid MD5, SHA1 for passwords. |
| Secrets Manager | Cryptographic key exposure through inadequate protection | Information Disclosure | 9.0 | High | Use hardware security modules (HSM), key rotation policies, and envelope encryption. |
| Secrets Manager | Weak key derivation functions allowing brute-force attacks | Spoofing | 6.8 | Medium | Use PBKDF2, bcrypt, or Argon2 with high work factors; avoid MD5, SHA1 for passwords. |
| Workloads OU | Session fixation or hijacking attacks | Spoofing | 9.0 | High | Regenerate session IDs after authentication, use HTTPOnly/Secure flags, implement session timeouts. |
| Workloads OU | Insecure password storage allowing credential theft | Information Disclosure | 8.8 | High | Hash passwords with Argon2id/bcrypt, add unique salts, enforce strong password policies. |
| Workloads OU | Missing or broken multi-factor authentication (MFA) | Spoofing | 6.4 | Medium | Enforce MFA for all privileged accounts, use TOTP/FIDO2, protect MFA bypass workflows. |
| Accessing using Merck SSO | Session fixation or hijacking attacks | Spoofing | 9.0 | High | Regenerate session IDs after authentication, use HTTPOnly/Secure flags, implement session timeouts. |
| Accessing using Merck SSO | Insecure password storage allowing credential theft | Information Disclosure | 8.8 | High | Hash passwords with Argon2id/bcrypt, add unique salts, enforce strong password policies. |
| Accessing using Merck SSO | Missing or broken multi-factor authentication (MFA) | Spoofing | 6.4 | Medium | Enforce MFA for all privileged accounts, use TOTP/FIDO2, protect MFA bypass workflows. |

## Detailed Findings
### Shared Service (Backup) - Prod – Lack of repudiation evidence for security-relevant actions
- STRIDE: Repudiation
- DREAD: Damage 6, Repro 6, Exploit 6, Users 6, Discover 6
- Average: 6.0 (Medium)
- Mitigation: Introduce tamper-proof logging with correlation IDs, user attribution, and retention policies.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/778.html, OWASP Top 10 2021: A09:2021### Shared Service (Backup) - Prod – Broken authentication allowing unauthorized API access
- STRIDE: Spoofing
- DREAD: Damage 10, Repro 10, Exploit 9, Users 8, Discover 8
- Average: 9.0 (High)
- Mitigation: Implement OAuth 2.0/OIDC, JWT validation, API key rotation, and rate limiting per identity.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/287.html, OWASP Top 10 2021: A07:2021### Shared Service (Backup) - Prod – Denial of service through resource exhaustion
- STRIDE: Denial of Service
- DREAD: Damage 6, Repro 7, Exploit 6, Users 6, Discover 6
- Average: 6.2 (Medium)
- Mitigation: Apply rate limiting, request size limits, connection pooling, and circuit breakers.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/400.html, OWASP Top 10 2021: A05:2021### Shared Service (Storage) - Prod – Lack of repudiation evidence for security-relevant actions
- STRIDE: Repudiation
- DREAD: Damage 7, Repro 6, Exploit 6, Users 7, Discover 6
- Average: 6.4 (Medium)
- Mitigation: Introduce tamper-proof logging with correlation IDs, user attribution, and retention policies.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/778.html, OWASP Top 10 2021: A09:2021### Shared Service (Storage) - Prod – Broken authentication allowing unauthorized API access
- STRIDE: Spoofing
- DREAD: Damage 10, Repro 10, Exploit 9, Users 9, Discover 8
- Average: 9.2 (High)
- Mitigation: Implement OAuth 2.0/OIDC, JWT validation, API key rotation, and rate limiting per identity.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/287.html, OWASP Top 10 2021: A07:2021### Shared Service (Storage) - Prod – Denial of service through resource exhaustion
- STRIDE: Denial of Service
- DREAD: Damage 7, Repro 7, Exploit 6, Users 7, Discover 6
- Average: 6.6 (Medium)
- Mitigation: Apply rate limiting, request size limits, connection pooling, and circuit breakers.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/400.html, OWASP Top 10 2021: A05:2021### Shared Service (Backup) - Non-Prod – Lack of repudiation evidence for security-relevant actions
- STRIDE: Repudiation
- DREAD: Damage 6, Repro 6, Exploit 6, Users 6, Discover 6
- Average: 6.0 (Medium)
- Mitigation: Introduce tamper-proof logging with correlation IDs, user attribution, and retention policies.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/778.html, OWASP Top 10 2021: A09:2021### Shared Service (Backup) - Non-Prod – Broken authentication allowing unauthorized API access
- STRIDE: Spoofing
- DREAD: Damage 10, Repro 10, Exploit 9, Users 8, Discover 8
- Average: 9.0 (High)
- Mitigation: Implement OAuth 2.0/OIDC, JWT validation, API key rotation, and rate limiting per identity.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/287.html, OWASP Top 10 2021: A07:2021### Shared Service (Backup) - Non-Prod – Denial of service through resource exhaustion
- STRIDE: Denial of Service
- DREAD: Damage 6, Repro 7, Exploit 6, Users 6, Discover 6
- Average: 6.2 (Medium)
- Mitigation: Apply rate limiting, request size limits, connection pooling, and circuit breakers.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/400.html, OWASP Top 10 2021: A05:2021### Shared Service (Storage) - Non-Prod – Lack of repudiation evidence for security-relevant actions
- STRIDE: Repudiation
- DREAD: Damage 7, Repro 6, Exploit 6, Users 7, Discover 6
- Average: 6.4 (Medium)
- Mitigation: Introduce tamper-proof logging with correlation IDs, user attribution, and retention policies.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/778.html, OWASP Top 10 2021: A09:2021### Shared Service (Storage) - Non-Prod – Broken authentication allowing unauthorized API access
- STRIDE: Spoofing
- DREAD: Damage 10, Repro 10, Exploit 9, Users 9, Discover 8
- Average: 9.2 (High)
- Mitigation: Implement OAuth 2.0/OIDC, JWT validation, API key rotation, and rate limiting per identity.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/287.html, OWASP Top 10 2021: A07:2021### Shared Service (Storage) - Non-Prod – Denial of service through resource exhaustion
- STRIDE: Denial of Service
- DREAD: Damage 7, Repro 7, Exploit 6, Users 7, Discover 6
- Average: 6.6 (Medium)
- Mitigation: Apply rate limiting, request size limits, connection pooling, and circuit breakers.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/400.html, OWASP Top 10 2021: A05:2021### Shared Service (DR) - Prod – Lack of repudiation evidence for security-relevant actions
- STRIDE: Repudiation
- DREAD: Damage 6, Repro 6, Exploit 6, Users 6, Discover 6
- Average: 6.0 (Medium)
- Mitigation: Introduce tamper-proof logging with correlation IDs, user attribution, and retention policies.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/778.html, OWASP Top 10 2021: A09:2021### Shared Service (DR) - Prod – Broken authentication allowing unauthorized API access
- STRIDE: Spoofing
- DREAD: Damage 10, Repro 10, Exploit 9, Users 8, Discover 8
- Average: 9.0 (High)
- Mitigation: Implement OAuth 2.0/OIDC, JWT validation, API key rotation, and rate limiting per identity.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/287.html, OWASP Top 10 2021: A07:2021### Shared Service (DR) - Prod – Denial of service through resource exhaustion
- STRIDE: Denial of Service
- DREAD: Damage 6, Repro 7, Exploit 6, Users 6, Discover 6
- Average: 6.2 (Medium)
- Mitigation: Apply rate limiting, request size limits, connection pooling, and circuit breakers.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/400.html, OWASP Top 10 2021: A05:2021### Component Pe-6Z7vc4aFHUBcSmwPr-53->Component CC8SS4oqa_s0rqLthlYS-36 – Unauthenticated cross-boundary communication allowing spoofing
- STRIDE: Spoofing
- DREAD: Damage 6, Repro 8, Exploit 6, Users 6, Discover 6
- Average: 6.4 (Medium)
- Mitigation: Add mutual TLS (mTLS), service mesh authentication, and network segmentation policies.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/306.html, OWASP Top 10 2021: A07:2021### Component Pe-6Z7vc4aFHUBcSmwPr-53->Component CC8SS4oqa_s0rqLthlYS-36 – Insufficient network segmentation allowing lateral movement
- STRIDE: Elevation of Privilege
- DREAD: Damage 10, Repro 10, Exploit 9, Users 8, Discover 8
- Average: 9.0 (High)
- Mitigation: Implement zero-trust networking, microsegmentation, and least-privilege firewall rules.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/668.html, OWASP Top 10 2021: A01:2021### Component Pe-6Z7vc4aFHUBcSmwPr-53->Component CC8SS4oqa_s0rqLthlYS-36 – Unauthenticated cross-boundary communication allowing spoofing
- STRIDE: Spoofing
- DREAD: Damage 6, Repro 8, Exploit 6, Users 6, Discover 6
- Average: 6.4 (Medium)
- Mitigation: Add mutual TLS (mTLS), service mesh authentication, and network segmentation policies.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/306.html, OWASP Top 10 2021: A07:2021### Component Pe-6Z7vc4aFHUBcSmwPr-53->Component CC8SS4oqa_s0rqLthlYS-36 – Insufficient network segmentation allowing lateral movement
- STRIDE: Elevation of Privilege
- DREAD: Damage 10, Repro 10, Exploit 9, Users 8, Discover 8
- Average: 9.0 (High)
- Mitigation: Implement zero-trust networking, microsegmentation, and least-privilege firewall rules.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/668.html, OWASP Top 10 2021: A01:2021### Transit Gateway->Component Pe-6Z7vc4aFHUBcSmwPr-53 – Unauthenticated cross-boundary communication allowing spoofing
- STRIDE: Spoofing
- DREAD: Damage 6, Repro 8, Exploit 6, Users 6, Discover 6
- Average: 6.4 (Medium)
- Mitigation: Add mutual TLS (mTLS), service mesh authentication, and network segmentation policies.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/306.html, OWASP Top 10 2021: A07:2021### Transit Gateway->Component Pe-6Z7vc4aFHUBcSmwPr-53 – Insufficient network segmentation allowing lateral movement
- STRIDE: Elevation of Privilege
- DREAD: Damage 10, Repro 10, Exploit 9, Users 8, Discover 8
- Average: 9.0 (High)
- Mitigation: Implement zero-trust networking, microsegmentation, and least-privilege firewall rules.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/668.html, OWASP Top 10 2021: A01:2021### Transit Gateway->Component Pe-6Z7vc4aFHUBcSmwPr-53 – Unauthenticated cross-boundary communication allowing spoofing
- STRIDE: Spoofing
- DREAD: Damage 6, Repro 8, Exploit 6, Users 6, Discover 6
- Average: 6.4 (Medium)
- Mitigation: Add mutual TLS (mTLS), service mesh authentication, and network segmentation policies.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/306.html, OWASP Top 10 2021: A07:2021### Transit Gateway->Component Pe-6Z7vc4aFHUBcSmwPr-53 – Insufficient network segmentation allowing lateral movement
- STRIDE: Elevation of Privilege
- DREAD: Damage 10, Repro 10, Exploit 9, Users 8, Discover 8
- Average: 9.0 (High)
- Mitigation: Implement zero-trust networking, microsegmentation, and least-privilege firewall rules.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/668.html, OWASP Top 10 2021: A01:2021### Component CC8SS4oqa_s0rqLthlYS-36->Component Pe-6Z7vc4aFHUBcSmwPr-66 – Unauthenticated cross-boundary communication allowing spoofing
- STRIDE: Spoofing
- DREAD: Damage 6, Repro 8, Exploit 6, Users 6, Discover 6
- Average: 6.4 (Medium)
- Mitigation: Add mutual TLS (mTLS), service mesh authentication, and network segmentation policies.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/306.html, OWASP Top 10 2021: A07:2021### Component CC8SS4oqa_s0rqLthlYS-36->Component Pe-6Z7vc4aFHUBcSmwPr-66 – Insufficient network segmentation allowing lateral movement
- STRIDE: Elevation of Privilege
- DREAD: Damage 10, Repro 10, Exploit 9, Users 8, Discover 8
- Average: 9.0 (High)
- Mitigation: Implement zero-trust networking, microsegmentation, and least-privilege firewall rules.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/668.html, OWASP Top 10 2021: A01:2021### Component CC8SS4oqa_s0rqLthlYS-36->Component 0kTWfv4hnWPTGup1sJnH-3 – Unauthenticated cross-boundary communication allowing spoofing
- STRIDE: Spoofing
- DREAD: Damage 6, Repro 8, Exploit 6, Users 6, Discover 6
- Average: 6.4 (Medium)
- Mitigation: Add mutual TLS (mTLS), service mesh authentication, and network segmentation policies.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/306.html, OWASP Top 10 2021: A07:2021### Component CC8SS4oqa_s0rqLthlYS-36->Component 0kTWfv4hnWPTGup1sJnH-3 – Insufficient network segmentation allowing lateral movement
- STRIDE: Elevation of Privilege
- DREAD: Damage 10, Repro 10, Exploit 9, Users 8, Discover 8
- Average: 9.0 (High)
- Mitigation: Implement zero-trust networking, microsegmentation, and least-privilege firewall rules.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/668.html, OWASP Top 10 2021: A01:2021### Component CC8SS4oqa_s0rqLthlYS-36->Component 0kTWfv4hnWPTGup1sJnH-2 – Unauthenticated cross-boundary communication allowing spoofing
- STRIDE: Spoofing
- DREAD: Damage 6, Repro 8, Exploit 6, Users 6, Discover 6
- Average: 6.4 (Medium)
- Mitigation: Add mutual TLS (mTLS), service mesh authentication, and network segmentation policies.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/306.html, OWASP Top 10 2021: A07:2021### Component CC8SS4oqa_s0rqLthlYS-36->Component 0kTWfv4hnWPTGup1sJnH-2 – Insufficient network segmentation allowing lateral movement
- STRIDE: Elevation of Privilege
- DREAD: Damage 10, Repro 10, Exploit 9, Users 8, Discover 8
- Average: 9.0 (High)
- Mitigation: Implement zero-trust networking, microsegmentation, and least-privilege firewall rules.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/668.html, OWASP Top 10 2021: A01:2021### KMS – Cryptographic key exposure through inadequate protection
- STRIDE: Information Disclosure
- DREAD: Damage 10, Repro 8, Exploit 10, Users 8, Discover 8
- Average: 8.8 (High)
- Mitigation: Use hardware security modules (HSM), key rotation policies, and envelope encryption.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/320.html, OWASP Top 10 2021: A02:2021### KMS – Weak key derivation functions allowing brute-force attacks
- STRIDE: Spoofing
- DREAD: Damage 6, Repro 8, Exploit 6, Users 6, Discover 6
- Average: 6.4 (Medium)
- Mitigation: Use PBKDF2, bcrypt, or Argon2 with high work factors; avoid MD5, SHA1 for passwords.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/916.html, OWASP Top 10 2021: A02:2021### Secrets Manager – Cryptographic key exposure through inadequate protection
- STRIDE: Information Disclosure
- DREAD: Damage 10, Repro 8, Exploit 10, Users 9, Discover 8
- Average: 9.0 (High)
- Mitigation: Use hardware security modules (HSM), key rotation policies, and envelope encryption.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/320.html, OWASP Top 10 2021: A02:2021### Secrets Manager – Weak key derivation functions allowing brute-force attacks
- STRIDE: Spoofing
- DREAD: Damage 7, Repro 8, Exploit 6, Users 7, Discover 6
- Average: 6.8 (Medium)
- Mitigation: Use PBKDF2, bcrypt, or Argon2 with high work factors; avoid MD5, SHA1 for passwords.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/916.html, OWASP Top 10 2021: A02:2021### Workloads OU – Session fixation or hijacking attacks
- STRIDE: Spoofing
- DREAD: Damage 10, Repro 10, Exploit 9, Users 8, Discover 8
- Average: 9.0 (High)
- Mitigation: Regenerate session IDs after authentication, use HTTPOnly/Secure flags, implement session timeouts.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/384.html, OWASP Top 10 2021: A07:2021### Workloads OU – Insecure password storage allowing credential theft
- STRIDE: Information Disclosure
- DREAD: Damage 10, Repro 8, Exploit 10, Users 8, Discover 8
- Average: 8.8 (High)
- Mitigation: Hash passwords with Argon2id/bcrypt, add unique salts, enforce strong password policies.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/256.html, OWASP Top 10 2021: A02:2021### Workloads OU – Missing or broken multi-factor authentication (MFA)
- STRIDE: Spoofing
- DREAD: Damage 6, Repro 8, Exploit 6, Users 6, Discover 6
- Average: 6.4 (Medium)
- Mitigation: Enforce MFA for all privileged accounts, use TOTP/FIDO2, protect MFA bypass workflows.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/308.html, OWASP Top 10 2021: A07:2021### Accessing using Merck SSO – Session fixation or hijacking attacks
- STRIDE: Spoofing
- DREAD: Damage 10, Repro 10, Exploit 9, Users 8, Discover 8
- Average: 9.0 (High)
- Mitigation: Regenerate session IDs after authentication, use HTTPOnly/Secure flags, implement session timeouts.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/384.html, OWASP Top 10 2021: A07:2021### Accessing using Merck SSO – Insecure password storage allowing credential theft
- STRIDE: Information Disclosure
- DREAD: Damage 10, Repro 8, Exploit 10, Users 8, Discover 8
- Average: 8.8 (High)
- Mitigation: Hash passwords with Argon2id/bcrypt, add unique salts, enforce strong password policies.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/256.html, OWASP Top 10 2021: A02:2021### Accessing using Merck SSO – Missing or broken multi-factor authentication (MFA)
- STRIDE: Spoofing
- DREAD: Damage 6, Repro 8, Exploit 6, Users 6, Discover 6
- Average: 6.4 (Medium)
- Mitigation: Enforce MFA for all privileged accounts, use TOTP/FIDO2, protect MFA bypass workflows.
- Methodology: STRIDE/DREAD
- References: https://cwe.mitre.org/data/definitions/308.html, OWASP Top 10 2021: A07:2021