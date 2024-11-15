# complex_system Threat Model

| Component | Threat | STRIDE | DREAD Avg | Risk Level | Mitigation |
|-----------|--------|--------|-----------|------------|------------|
| Partner Service | Lack of repudiation evidence | Repudiation | 6.0 | Medium | Introduce tamper-proof logging with correlation IDs and retention policies. |
| API Gateway | Lack of repudiation evidence | Repudiation | 6.0 | Medium | Introduce tamper-proof logging with correlation IDs and retention policies. |
| Auth Service | Lack of repudiation evidence | Repudiation | 6.0 | Medium | Introduce tamper-proof logging with correlation IDs and retention policies. |
| Session Store | Tampering with stored data | Tampering | 7.2 | Medium | Ensure integrity controls (signatures, versioning) and access restrictions on data stores. |
| Session Store | Sensitive data disclosure | Information Disclosure | 7.2 | Medium | Encrypt data at rest and enforce least-privilege access policies. |
| Payment API | Lack of repudiation evidence | Repudiation | 6.0 | Medium | Introduce tamper-proof logging with correlation IDs and retention policies. |
| Order Service | Lack of repudiation evidence | Repudiation | 6.0 | Medium | Introduce tamper-proof logging with correlation IDs and retention policies. |
| Inventory Service | Lack of repudiation evidence | Repudiation | 6.0 | Medium | Introduce tamper-proof logging with correlation IDs and retention policies. |
| Card Vault | Tampering with stored data | Tampering | 7.2 | Medium | Ensure integrity controls (signatures, versioning) and access restrictions on data stores. |
| Card Vault | Sensitive data disclosure | Information Disclosure | 7.2 | Medium | Encrypt data at rest and enforce least-privilege access policies. |
| Tokenization Service | Lack of repudiation evidence | Repudiation | 6.0 | Medium | Introduce tamper-proof logging with correlation IDs and retention policies. |
| PCI Audit Logs | Tampering with stored data | Tampering | 7.2 | Medium | Ensure integrity controls (signatures, versioning) and access restrictions on data stores. |
| PCI Audit Logs | Sensitive data disclosure | Information Disclosure | 7.2 | Medium | Encrypt data at rest and enforce least-privilege access policies. |
| Data Lake | Tampering with stored data | Tampering | 7.2 | Medium | Ensure integrity controls (signatures, versioning) and access restrictions on data stores. |
| Data Lake | Sensitive data disclosure | Information Disclosure | 7.2 | Medium | Encrypt data at rest and enforce least-privilege access policies. |
| Mobile App->API Gateway | Unauthenticated cross-boundary communication | Spoofing | 6.2 | Medium | Add mutual authentication and allow-lists for cross-boundary traffic. |
| Partner Service->API Gateway | Unauthenticated cross-boundary communication | Spoofing | 6.2 | Medium | Add mutual authentication and allow-lists for cross-boundary traffic. |
| Potential Attacker->Web Application Firewall | Unauthenticated cross-boundary communication | Spoofing | 6.2 | Medium | Add mutual authentication and allow-lists for cross-boundary traffic. |
| Auth Service->Session Store | Credential replay or brute-force against authentication flow | Spoofing | 8.8 | High | Add rate limiting, anomaly detection, and MFA on authentication endpoints. |
| Auth Service->Payment API | Unauthenticated cross-boundary communication | Spoofing | 6.2 | Medium | Add mutual authentication and allow-lists for cross-boundary traffic. |
| Auth Service->Payment API | Credential replay or brute-force against authentication flow | Spoofing | 8.8 | High | Add rate limiting, anomaly detection, and MFA on authentication endpoints. |
| Payment API->Tokenization Service | Unauthenticated cross-boundary communication | Spoofing | 6.2 | Medium | Add mutual authentication and allow-lists for cross-boundary traffic. |
| Risk Engine->External Payment Processor | Unauthenticated cross-boundary communication | Spoofing | 6.2 | Medium | Add mutual authentication and allow-lists for cross-boundary traffic. |
| External Payment Processor->Tokenization Service | Unauthenticated cross-boundary communication | Spoofing | 6.2 | Medium | Add mutual authentication and allow-lists for cross-boundary traffic. |
| Event Bus->Data Lake | Unauthenticated cross-boundary communication | Spoofing | 6.2 | Medium | Add mutual authentication and allow-lists for cross-boundary traffic. |
| Data Lake->ETL Pipeline | Resource exhaustion through scheduled operations | Denial of Service | 6.0 | Medium | Add capacity planning, circuit breakers, and backpressure controls for scheduled jobs. |
| Security Operations->Event Bus | Unauthenticated cross-boundary communication | Spoofing | 6.2 | Medium | Add mutual authentication and allow-lists for cross-boundary traffic. |
| Session Store->Data Lake | Unauthenticated cross-boundary communication | Spoofing | 6.2 | Medium | Add mutual authentication and allow-lists for cross-boundary traffic. |
| Auth Service->Data Lake | Unauthenticated cross-boundary communication | Spoofing | 6.2 | Medium | Add mutual authentication and allow-lists for cross-boundary traffic. |
| Auth Service->Data Lake | Credential replay or brute-force against authentication flow | Spoofing | 8.8 | High | Add rate limiting, anomaly detection, and MFA on authentication endpoints. |
| API Gateway->Data Lake | Unauthenticated cross-boundary communication | Spoofing | 6.2 | Medium | Add mutual authentication and allow-lists for cross-boundary traffic. |
| Potential Attacker->Event Bus | Unauthenticated cross-boundary communication | Spoofing | 6.2 | Medium | Add mutual authentication and allow-lists for cross-boundary traffic. |

## Detailed Findings
### Partner Service – Lack of repudiation evidence
- STRIDE: Repudiation
- DREAD: Damage 6, Repro 6, Exploit 6, Users 6, Discover 6
- Average: 6.0 (Medium)
- Mitigation: Introduce tamper-proof logging with correlation IDs and retention policies.
### API Gateway – Lack of repudiation evidence
- STRIDE: Repudiation
- DREAD: Damage 6, Repro 6, Exploit 6, Users 6, Discover 6
- Average: 6.0 (Medium)
- Mitigation: Introduce tamper-proof logging with correlation IDs and retention policies.
### Auth Service – Lack of repudiation evidence
- STRIDE: Repudiation
- DREAD: Damage 6, Repro 6, Exploit 6, Users 6, Discover 6
- Average: 6.0 (Medium)
- Mitigation: Introduce tamper-proof logging with correlation IDs and retention policies.
### Session Store – Tampering with stored data
- STRIDE: Tampering
- DREAD: Damage 7, Repro 7, Exploit 8, Users 7, Discover 7
- Average: 7.2 (Medium)
- Mitigation: Ensure integrity controls (signatures, versioning) and access restrictions on data stores.
### Session Store – Sensitive data disclosure
- STRIDE: Information Disclosure
- DREAD: Damage 7, Repro 7, Exploit 8, Users 7, Discover 7
- Average: 7.2 (Medium)
- Mitigation: Encrypt data at rest and enforce least-privilege access policies.
### Payment API – Lack of repudiation evidence
- STRIDE: Repudiation
- DREAD: Damage 6, Repro 6, Exploit 6, Users 6, Discover 6
- Average: 6.0 (Medium)
- Mitigation: Introduce tamper-proof logging with correlation IDs and retention policies.
### Order Service – Lack of repudiation evidence
- STRIDE: Repudiation
- DREAD: Damage 6, Repro 6, Exploit 6, Users 6, Discover 6
- Average: 6.0 (Medium)
- Mitigation: Introduce tamper-proof logging with correlation IDs and retention policies.
### Inventory Service – Lack of repudiation evidence
- STRIDE: Repudiation
- DREAD: Damage 6, Repro 6, Exploit 6, Users 6, Discover 6
- Average: 6.0 (Medium)
- Mitigation: Introduce tamper-proof logging with correlation IDs and retention policies.
### Card Vault – Tampering with stored data
- STRIDE: Tampering
- DREAD: Damage 7, Repro 7, Exploit 8, Users 7, Discover 7
- Average: 7.2 (Medium)
- Mitigation: Ensure integrity controls (signatures, versioning) and access restrictions on data stores.
### Card Vault – Sensitive data disclosure
- STRIDE: Information Disclosure
- DREAD: Damage 7, Repro 7, Exploit 8, Users 7, Discover 7
- Average: 7.2 (Medium)
- Mitigation: Encrypt data at rest and enforce least-privilege access policies.
### Tokenization Service – Lack of repudiation evidence
- STRIDE: Repudiation
- DREAD: Damage 6, Repro 6, Exploit 6, Users 6, Discover 6
- Average: 6.0 (Medium)
- Mitigation: Introduce tamper-proof logging with correlation IDs and retention policies.
### PCI Audit Logs – Tampering with stored data
- STRIDE: Tampering
- DREAD: Damage 7, Repro 7, Exploit 8, Users 7, Discover 7
- Average: 7.2 (Medium)
- Mitigation: Ensure integrity controls (signatures, versioning) and access restrictions on data stores.
### PCI Audit Logs – Sensitive data disclosure
- STRIDE: Information Disclosure
- DREAD: Damage 7, Repro 7, Exploit 8, Users 7, Discover 7
- Average: 7.2 (Medium)
- Mitigation: Encrypt data at rest and enforce least-privilege access policies.
### Data Lake – Tampering with stored data
- STRIDE: Tampering
- DREAD: Damage 7, Repro 7, Exploit 8, Users 7, Discover 7
- Average: 7.2 (Medium)
- Mitigation: Ensure integrity controls (signatures, versioning) and access restrictions on data stores.
### Data Lake – Sensitive data disclosure
- STRIDE: Information Disclosure
- DREAD: Damage 7, Repro 7, Exploit 8, Users 7, Discover 7
- Average: 7.2 (Medium)
- Mitigation: Encrypt data at rest and enforce least-privilege access policies.
### Mobile App->API Gateway – Unauthenticated cross-boundary communication
- STRIDE: Spoofing
- DREAD: Damage 6, Repro 7, Exploit 6, Users 6, Discover 6
- Average: 6.2 (Medium)
- Mitigation: Add mutual authentication and allow-lists for cross-boundary traffic.
### Partner Service->API Gateway – Unauthenticated cross-boundary communication
- STRIDE: Spoofing
- DREAD: Damage 6, Repro 7, Exploit 6, Users 6, Discover 6
- Average: 6.2 (Medium)
- Mitigation: Add mutual authentication and allow-lists for cross-boundary traffic.
### Potential Attacker->Web Application Firewall – Unauthenticated cross-boundary communication
- STRIDE: Spoofing
- DREAD: Damage 6, Repro 7, Exploit 6, Users 6, Discover 6
- Average: 6.2 (Medium)
- Mitigation: Add mutual authentication and allow-lists for cross-boundary traffic.
### Auth Service->Session Store – Credential replay or brute-force against authentication flow
- STRIDE: Spoofing
- DREAD: Damage 10, Repro 9, Exploit 9, Users 8, Discover 8
- Average: 8.8 (High)
- Mitigation: Add rate limiting, anomaly detection, and MFA on authentication endpoints.
### Auth Service->Payment API – Unauthenticated cross-boundary communication
- STRIDE: Spoofing
- DREAD: Damage 6, Repro 7, Exploit 6, Users 6, Discover 6
- Average: 6.2 (Medium)
- Mitigation: Add mutual authentication and allow-lists for cross-boundary traffic.
### Auth Service->Payment API – Credential replay or brute-force against authentication flow
- STRIDE: Spoofing
- DREAD: Damage 10, Repro 9, Exploit 9, Users 8, Discover 8
- Average: 8.8 (High)
- Mitigation: Add rate limiting, anomaly detection, and MFA on authentication endpoints.
### Payment API->Tokenization Service – Unauthenticated cross-boundary communication
- STRIDE: Spoofing
- DREAD: Damage 6, Repro 7, Exploit 6, Users 6, Discover 6
- Average: 6.2 (Medium)
- Mitigation: Add mutual authentication and allow-lists for cross-boundary traffic.
### Risk Engine->External Payment Processor – Unauthenticated cross-boundary communication
- STRIDE: Spoofing
- DREAD: Damage 6, Repro 7, Exploit 6, Users 6, Discover 6
- Average: 6.2 (Medium)
- Mitigation: Add mutual authentication and allow-lists for cross-boundary traffic.
### External Payment Processor->Tokenization Service – Unauthenticated cross-boundary communication
- STRIDE: Spoofing
- DREAD: Damage 6, Repro 7, Exploit 6, Users 6, Discover 6
- Average: 6.2 (Medium)
- Mitigation: Add mutual authentication and allow-lists for cross-boundary traffic.
### Event Bus->Data Lake – Unauthenticated cross-boundary communication
- STRIDE: Spoofing
- DREAD: Damage 6, Repro 7, Exploit 6, Users 6, Discover 6
- Average: 6.2 (Medium)
- Mitigation: Add mutual authentication and allow-lists for cross-boundary traffic.
### Data Lake->ETL Pipeline – Resource exhaustion through scheduled operations
- STRIDE: Denial of Service
- DREAD: Damage 6, Repro 6, Exploit 6, Users 6, Discover 6
- Average: 6.0 (Medium)
- Mitigation: Add capacity planning, circuit breakers, and backpressure controls for scheduled jobs.
### Security Operations->Event Bus – Unauthenticated cross-boundary communication
- STRIDE: Spoofing
- DREAD: Damage 6, Repro 7, Exploit 6, Users 6, Discover 6
- Average: 6.2 (Medium)
- Mitigation: Add mutual authentication and allow-lists for cross-boundary traffic.
### Session Store->Data Lake – Unauthenticated cross-boundary communication
- STRIDE: Spoofing
- DREAD: Damage 6, Repro 7, Exploit 6, Users 6, Discover 6
- Average: 6.2 (Medium)
- Mitigation: Add mutual authentication and allow-lists for cross-boundary traffic.
### Auth Service->Data Lake – Unauthenticated cross-boundary communication
- STRIDE: Spoofing
- DREAD: Damage 6, Repro 7, Exploit 6, Users 6, Discover 6
- Average: 6.2 (Medium)
- Mitigation: Add mutual authentication and allow-lists for cross-boundary traffic.
### Auth Service->Data Lake – Credential replay or brute-force against authentication flow
- STRIDE: Spoofing
- DREAD: Damage 10, Repro 9, Exploit 9, Users 8, Discover 8
- Average: 8.8 (High)
- Mitigation: Add rate limiting, anomaly detection, and MFA on authentication endpoints.
### API Gateway->Data Lake – Unauthenticated cross-boundary communication
- STRIDE: Spoofing
- DREAD: Damage 6, Repro 7, Exploit 6, Users 6, Discover 6
- Average: 6.2 (Medium)
- Mitigation: Add mutual authentication and allow-lists for cross-boundary traffic.
### Potential Attacker->Event Bus – Unauthenticated cross-boundary communication
- STRIDE: Spoofing
- DREAD: Damage 6, Repro 7, Exploit 6, Users 6, Discover 6
- Average: 6.2 (Medium)
- Mitigation: Add mutual authentication and allow-lists for cross-boundary traffic.
