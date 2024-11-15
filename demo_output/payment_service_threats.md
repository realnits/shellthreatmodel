# payment_service Threat Model

| Component | Threat | STRIDE | DREAD Avg | Risk Level | Mitigation |
|-----------|--------|--------|-----------|------------|------------|
| Payment DB | Tampering with stored data | Tampering | 7.2 | Medium | Ensure integrity controls (signatures, versioning) and access restrictions on data stores. |
| Payment DB | Sensitive data disclosure | Information Disclosure | 7.2 | Medium | Encrypt data at rest and enforce least-privilege access policies. |
| frontend->auth | Credential replay or brute-force against authentication flow | Spoofing | 8.8 | High | Add rate limiting, anomaly detection, and MFA on authentication endpoints. |
| auth->Payment DB | Unauthenticated cross-boundary communication | Spoofing | 6.2 | Medium | Add mutual authentication and allow-lists for cross-boundary traffic. |
| auth->Payment DB | Credential replay or brute-force against authentication flow | Spoofing | 8.8 | High | Add rate limiting, anomaly detection, and MFA on authentication endpoints. |
| worker->Payment DB | Unauthenticated cross-boundary communication | Spoofing | 6.2 | Medium | Add mutual authentication and allow-lists for cross-boundary traffic. |

## Detailed Findings
### Payment DB – Tampering with stored data
- STRIDE: Tampering
- DREAD: Damage 7, Repro 7, Exploit 8, Users 7, Discover 7
- Average: 7.2 (Medium)
- Mitigation: Ensure integrity controls (signatures, versioning) and access restrictions on data stores.
### Payment DB – Sensitive data disclosure
- STRIDE: Information Disclosure
- DREAD: Damage 7, Repro 7, Exploit 8, Users 7, Discover 7
- Average: 7.2 (Medium)
- Mitigation: Encrypt data at rest and enforce least-privilege access policies.
### frontend->auth – Credential replay or brute-force against authentication flow
- STRIDE: Spoofing
- DREAD: Damage 10, Repro 9, Exploit 9, Users 8, Discover 8
- Average: 8.8 (High)
- Mitigation: Add rate limiting, anomaly detection, and MFA on authentication endpoints.
### auth->Payment DB – Unauthenticated cross-boundary communication
- STRIDE: Spoofing
- DREAD: Damage 6, Repro 7, Exploit 6, Users 6, Discover 6
- Average: 6.2 (Medium)
- Mitigation: Add mutual authentication and allow-lists for cross-boundary traffic.
### auth->Payment DB – Credential replay or brute-force against authentication flow
- STRIDE: Spoofing
- DREAD: Damage 10, Repro 9, Exploit 9, Users 8, Discover 8
- Average: 8.8 (High)
- Mitigation: Add rate limiting, anomaly detection, and MFA on authentication endpoints.
### worker->Payment DB – Unauthenticated cross-boundary communication
- STRIDE: Spoofing
- DREAD: Damage 6, Repro 7, Exploit 6, Users 6, Discover 6
- Average: 6.2 (Medium)
- Mitigation: Add mutual authentication and allow-lists for cross-boundary traffic.
