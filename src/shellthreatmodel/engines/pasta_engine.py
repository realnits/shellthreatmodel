"""PASTA (Process for Attack Simulation and Threat Analysis) engine with complete 7-stage methodology."""

from __future__ import annotations

from typing import Iterable

from shellthreatmodel.engines.base import (
    ThreatEngine,
    is_sensitive_zone,
    is_external_zone,
    is_sensitive_component,
    is_public_facing,
    is_privileged_component,
    is_cloud_component,
)
from shellthreatmodel.models.architecture import ArchitectureModel, Component, DataFlow
from shellthreatmodel.models.threat import DreadScore, StrideCategory, Threat


# MITRE ATT&CK Tactics mapping
ATTACK_TACTICS = {
    "initial_access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege_escalation": "TA0004",
    "defense_evasion": "TA0005",
    "credential_access": "TA0006",
    "discovery": "TA0007",
    "lateral_movement": "TA0008",
    "collection": "TA0009",
    "exfiltration": "TA0010",
    "impact": "TA0040",
    "command_and_control": "TA0011",
    "resource_development": "TA0042",
    "reconnaissance": "TA0043",
}

# MITRE ATT&CK Techniques mapping for common threats
ATTACK_TECHNIQUES = {
    "sql_injection": "T1190",
    "phishing": "T1566",
    "brute_force": "T1110",
    "exploit_public_app": "T1190",
    "valid_accounts": "T1078",
    "data_encrypted": "T1486",
    "exfiltration_over_c2": "T1041",
    "steal_application_tokens": "T1528",
    "supply_chain_compromise": "T1195",
    "trusted_relationship": "T1199",
    "container_escape": "T1611",
    "serverless_execution": "T1648",
}


class PASTAThreatEngine(ThreatEngine):
    """Generate threat scenarios aligned with the complete PASTA methodology."""

    name = "pasta"

    def generate(self, architecture: ArchitectureModel) -> Iterable[Threat]:
        trust_lookup = self._trust_zone_lookup(architecture)
        sensitive_zones = {name for name in trust_lookup.values() if name and is_sensitive_zone(name)}
        external_zones = {name for name in trust_lookup.values() if name and is_external_zone(name)}

        threats: list[Threat] = []
        
        # PASTA Stage 1-3: Business objectives, technical scope, decomposition (implicit in architecture model)
        # These stages inform our analysis but don't generate discrete threats
        
        # PASTA Stage 4: Threat analysis - identify attack surface
        threats.extend(self._step4_surface_analysis(architecture, trust_lookup, external_zones))
        
        # PASTA Stage 5: Vulnerability and weakness analysis
        threats.extend(self._step5_weakness_analysis(architecture, trust_lookup, external_zones, sensitive_zones))
        
        # PASTA Stage 6: Attack modeling and simulation
        threats.extend(self._step6_attack_modeling(architecture, trust_lookup, sensitive_zones))
        threats.extend(self._step6_supply_chain_threats(architecture, trust_lookup))
        threats.extend(self._step6_insider_threats(architecture, trust_lookup, sensitive_zones))
        
        # PASTA Stage 7: Risk and impact analysis
        threats.extend(self._step7_risk_analysis(architecture))
        threats.extend(self._step7_cloud_threats(architecture, trust_lookup))
        
        return threats

    def _step4_surface_analysis(
        self,
        architecture: ArchitectureModel,
        trust_lookup: dict[str, str],
        external_zones: set[str],
    ) -> Iterable[Threat]:
        """PASTA Stage 4: Threat Analysis - Identify attack surface and entry points."""
        for component in architecture.components:
            zone = trust_lookup.get(component.name, "")
            comp_type_lower = component.type.lower()
            
            # External-facing components represent attack surface
            if zone and zone in external_zones:
                description = (
                    f"[PASTA Stage 4] Attackers enumerate exposed service '{component.name}' in zone '{zone}' "
                    "to discover misconfigurations, outdated software, or vulnerable endpoints."
                )
                yield self._threat(
                    component.name,
                    description,
                    StrideCategory.INFORMATION_DISCLOSURE,
                    "Apply attack surface management tools, hardened configuration baselines, WAF, and continuous vulnerability scanning.",
                    stage=4,
                    stage_title="Threat Analysis",
                    severity="medium",
                    sensitive=is_sensitive_component(component),
                    attack_tactic=ATTACK_TACTICS["discovery"],
                )
            
            # Public APIs are high-value targets
            if comp_type_lower in {"api", "rest", "graphql", "grpc"} and ("public" in component.name.lower() or zone in external_zones):
                description = (
                    f"[PASTA Stage 4] Public API '{component.name}' exposes endpoints susceptible to enumeration, "
                    "brute force, or injection attacks from untrusted sources."
                )
                yield self._threat(
                    component.name,
                    description,
                    StrideCategory.TAMPERING,
                    "Implement API gateway with rate limiting, input validation, authentication, and schema enforcement.",
                    stage=4,
                    stage_title="Threat Analysis",
                    severity="high",
                    sensitive=True,
                    attack_tactic=ATTACK_TACTICS["initial_access"],
                )

    def _step5_weakness_analysis(
        self,
        architecture: ArchitectureModel,
        trust_lookup: dict[str, str],
        external_zones: set[str],
        sensitive_zones: set[str],
    ) -> Iterable[Threat]:
        """PASTA Stage 5: Vulnerability & Weakness Analysis - Analyze attack paths and technical weaknesses."""
        for flow in architecture.data_flows:
            source_zone = trust_lookup.get(flow.source, "")
            destination_zone = trust_lookup.get(flow.destination, "")
            if not source_zone or not destination_zone or source_zone == destination_zone:
                continue

            severity = "medium"
            attack_tactic = ATTACK_TACTICS["lateral_movement"]
            
            # Critical path: External → Sensitive
            if source_zone in external_zones and destination_zone in sensitive_zones:
                severity = "high"
                attack_tactic = ATTACK_TACTICS["initial_access"]
                description = (
                    f"[PASTA Stage 5] Critical attack path from external zone '{source_zone}' ('{flow.source}') "
                    f"to sensitive zone '{destination_zone}' ('{flow.destination}') represents high-risk entry vector "
                    "exploitable if boundary controls fail or are bypassed."
                )
            else:
                description = (
                    f"[PASTA Stage 5] Attack path from '{flow.source}' ({source_zone or 'unknown zone'}) "
                    f"to '{flow.destination}' ({destination_zone or 'unknown zone'}) "
                    "is exploitable if boundary controls fail, enabling lateral movement."
                )
            
            mitigation = "Enforce mutual authentication (mTLS), network segmentation (zero-trust), IDS/IPS, and anomaly detection on boundary crossings."
            if flow.sensitive:
                mitigation = (
                    "Enforce mutual authentication (mTLS), network segmentation (zero-trust), data sensitivity tagging, "
                    "encryption in transit, IDS/IPS, and anomaly detection on boundary crossings."
                )
            
            yield self._threat(
                f"{flow.source}->{flow.destination}",
                description,
                StrideCategory.SPOOFING,
                mitigation,
                stage=5,
                stage_title="Weakness & Vulnerability Analysis",
                severity=severity,
                sensitive=flow.sensitive,
                attack_tactic=attack_tactic,
            )
            
            # Protocol weaknesses
            if flow.protocol:
                protocol_lower = flow.protocol.lower()
                if protocol_lower in {"http", "ftp", "telnet", "smtp"} and flow.sensitive:
                    description = (
                        f"[PASTA Stage 5] Cleartext protocol '{flow.protocol}' on sensitive flow '{flow.source}→{flow.destination}' "
                        "exposes data to interception, man-in-the-middle attacks, and eavesdropping."
                    )
                    yield self._threat(
                        f"{flow.source}->{flow.destination}",
                        description,
                        StrideCategory.INFORMATION_DISCLOSURE,
                        "Replace with TLS 1.2+ secured protocols (HTTPS, SFTP, SSH), enforce certificate validation.",
                        stage=5,
                        stage_title="Weakness & Vulnerability Analysis",
                        severity="high",
                        sensitive=True,
                        attack_tactic=ATTACK_TACTICS["credential_access"],
                    )

    def _step6_attack_modeling(
        self,
        architecture: ArchitectureModel,
        trust_lookup: dict[str, str],
        sensitive_zones: set[str],
    ) -> Iterable[Threat]:
        """PASTA Stage 6: Attack Modeling & Simulation - Model realistic attack scenarios and kill chains."""
        for component in architecture.components:
            comp_type_lower = component.type.lower()
            zone = trust_lookup.get(component.name, "")
            sensitive = _is_sensitive_component(component) or zone in sensitive_zones
            
            # Data stores are primary targets for exfiltration/impact
            if comp_type_lower in {"database", "datastore", "storage", "queue", "cache"}:
                # Kill chain: Initial Access → Collection → Exfiltration
                description = (
                    f"[PASTA Stage 6] Attack simulation targeting data store '{component.name}' follows kill chain: "
                    "(1) Initial access via application vulnerability, (2) Privilege escalation, "
                    "(3) Discovery of data schemas, (4) Collection of sensitive records, (5) Exfiltration or destruction."
                )
                yield self._threat(
                    component.name,
                    description,
                    StrideCategory.INFORMATION_DISCLOSURE if sensitive else StrideCategory.TAMPERING,
                    "Implement defense-in-depth: application firewalls, least-privilege DB access, query monitoring, "
                    "encryption (at-rest/in-transit), immutable backups, and just-in-time privileged access.",
                    stage=6,
                    stage_title="Attack Modeling & Simulation",
                    severity="high" if sensitive else "medium",
                    sensitive=sensitive,
                    attack_tactic=ATTACK_TACTICS["collection"],
                )
                
                # Ransomware/destructive attack scenario
                description = (
                    f"[PASTA Stage 6] Ransomware attack against '{component.name}' encrypts or corrupts data, "
                    "demanding payment or causing operational impact via data unavailability."
                )
                yield self._threat(
                    component.name,
                    description,
                    StrideCategory.DENIAL_OF_SERVICE,
                    "Deploy immutable backup strategy (3-2-1 rule), offline recovery procedures, endpoint protection, "
                    "and network segmentation to limit ransomware spread.",
                    stage=6,
                    stage_title="Attack Modeling & Simulation",
                    severity="high",
                    sensitive=sensitive,
                    attack_tactic=ATTACK_TACTICS["impact"],
                )
            
            # Authentication/authorization components
            if comp_type_lower in {"auth", "sso", "idp", "ldap", "ad"} or "auth" in component.name.lower():
                # Credential access kill chain
                description = (
                    f"[PASTA Stage 6] Credential harvesting attack on '{component.name}' follows kill chain: "
                    "(1) Phishing or password spraying, (2) Credential stuffing, (3) Session hijacking, "
                    "(4) Privilege escalation, (5) Persistence via golden ticket/token."
                )
                yield self._threat(
                    component.name,
                    description,
                    StrideCategory.SPOOFING,
                    "Enforce MFA, passwordless authentication (FIDO2), anomaly detection, session timeout, "
                    "credential rotation, and monitor for suspicious authentication patterns.",
                    stage=6,
                    stage_title="Attack Modeling & Simulation",
                    severity="high",
                    sensitive=True,
                    attack_tactic=ATTACK_TACTICS["credential_access"],
                )
            
            # Admin/privileged components
            if comp_type_lower in {"admin", "portal", "dashboard"} or "admin" in component.name.lower():
                # Privilege escalation kill chain
                description = (
                    f"[PASTA Stage 6] Privilege escalation attack targeting '{component.name}' follows kill chain: "
                    "(1) Compromise low-privilege account, (2) Exploit authorization flaw, "
                    "(3) Escalate to admin privileges, (4) Establish persistence, (5) Lateral movement to critical systems."
                )
                yield self._threat(
                    component.name,
                    description,
                    StrideCategory.ELEVATION_OF_PRIVILEGE,
                    "Implement RBAC with principle of least privilege, privileged access management (PAM), "
                    "session recording, MFA for admin actions, and regular access reviews.",
                    stage=6,
                    stage_title="Attack Modeling & Simulation",
                    severity="high",
                    sensitive=True,
                    attack_tactic=ATTACK_TACTICS["privilege_escalation"],
                )

    def _step6_supply_chain_threats(self, architecture: ArchitectureModel, trust_lookup: dict[str, str]) -> Iterable[Threat]:
        """PASTA Stage 6: Supply Chain Attack Modeling - Dependencies and third-party risks."""
        for component in architecture.components:
            comp_type_lower = component.type.lower()
            comp_name_lower = component.name.lower()
            
            # Third-party integrations and external dependencies
            if any(keyword in comp_type_lower or keyword in comp_name_lower for keyword in ["api", "service", "integration", "library", "sdk", "package"]):
                # Supply chain compromise
                description = (
                    f"[PASTA Stage 6] Supply chain attack targeting '{component.name}': "
                    "Attacker compromises upstream dependency or third-party service to inject malicious code, "
                    "backdoors, or data exfiltration mechanisms affecting all downstream consumers."
                )
                yield self._threat(
                    component.name,
                    description,
                    StrideCategory.TAMPERING,
                    "Implement software composition analysis (SCA), dependency pinning, SBOM generation, "
                    "signature verification, vendor security assessments, and runtime integrity monitoring.",
                    stage=6,
                    stage_title="Supply Chain Risk Analysis",
                    severity="high",
                    sensitive=is_sensitive_component(component),
                    attack_tactic=ATTACK_TACTICS["initial_access"],
                    attack_technique=ATTACK_TECHNIQUES["supply_chain_compromise"],
                )
            
            # Container images and base images
            if comp_type_lower in {"container", "docker", "kubernetes", "pod"}:
                description = (
                    f"[PASTA Stage 6] Compromised container image for '{component.name}' containing "
                    "vulnerable base layers, malicious packages, or embedded credentials exposing the runtime environment."
                )
                yield self._threat(
                    component.name,
                    description,
                    StrideCategory.ELEVATION_OF_PRIVILEGE,
                    "Scan images with Trivy/Snyk, use minimal base images (distroless), enforce image signing, "
                    "maintain private registry with admission controllers, and implement runtime security monitoring.",
                    stage=6,
                    stage_title="Supply Chain Risk Analysis",
                    severity="high",
                    sensitive=True,
                    attack_tactic=ATTACK_TACTICS["execution"],
                    attack_technique=ATTACK_TECHNIQUES["supply_chain_compromise"],
                )
            
            # CI/CD pipeline components
            if any(keyword in comp_type_lower or keyword in comp_name_lower for keyword in ["ci", "cd", "pipeline", "jenkins", "github", "gitlab", "build"]):
                description = (
                    f"[PASTA Stage 6] CI/CD pipeline compromise on '{component.name}': "
                    "Attacker gains access to build pipeline to inject malicious artifacts, steal secrets, "
                    "or modify deployment configurations affecting production systems."
                )
                yield self._threat(
                    component.name,
                    description,
                    StrideCategory.TAMPERING,
                    "Harden CI/CD with least-privilege service accounts, secret scanning, artifact signing, "
                    "pipeline-as-code reviews, audit logging, and isolated build environments.",
                    stage=6,
                    stage_title="Supply Chain Risk Analysis",
                    severity="high",
                    sensitive=True,
                    attack_tactic=ATTACK_TACTICS["execution"],
                    attack_technique=ATTACK_TECHNIQUES["supply_chain_compromise"],
                )

    def _step6_insider_threats(self, architecture: ArchitectureModel, trust_lookup: dict[str, str], sensitive_zones: set[str]) -> Iterable[Threat]:
        """PASTA Stage 6: Insider Threat Modeling - Malicious or negligent insider scenarios."""
        for component in architecture.components:
            comp_type_lower = component.type.lower()
            zone = trust_lookup.get(component.name, "")
            sensitive = _is_sensitive_component(component) or zone in sensitive_zones
            
            # Admin and privileged systems
            if comp_type_lower in {"admin", "portal", "dashboard"} or "admin" in component.name.lower():
                description = (
                    f"[PASTA Stage 6] Malicious insider with privileged access to '{component.name}' "
                    "exfiltrates sensitive data, creates backdoor accounts, or sabotages systems "
                    "while evading detection through legitimate access patterns."
                )
                yield self._threat(
                    component.name,
                    description,
                    StrideCategory.INFORMATION_DISCLOSURE,
                    "Implement user behavior analytics (UBA), privileged access management (PAM), "
                    "session recording, separation of duties, mandatory vacations, and data loss prevention (DLP).",
                    stage=6,
                    stage_title="Insider Threat Analysis",
                    severity="high",
                    sensitive=True,
                    attack_tactic=ATTACK_TACTICS["exfiltration"],
                )
            
            # Database and data stores
            if comp_type_lower in {"database", "datastore", "storage"} and sensitive:
                description = (
                    f"[PASTA Stage 6] Negligent insider misconfigures '{component.name}' permissions, "
                    "accidentally exposes sensitive data, or fails to apply security patches, "
                    "creating exploitable vulnerabilities."
                )
                yield self._threat(
                    component.name,
                    description,
                    StrideCategory.INFORMATION_DISCLOSURE,
                    "Automate configuration management, implement least-privilege by default, "
                    "provide security training, enforce peer reviews, and deploy configuration drift detection.",
                    stage=6,
                    stage_title="Insider Threat Analysis",
                    severity="medium",
                    sensitive=True,
                    attack_tactic=ATTACK_TACTICS["defense_evasion"],
                )

    def _step7_cloud_threats(self, architecture: ArchitectureModel, trust_lookup: dict[str, str]) -> Iterable[Threat]:
        """PASTA Stage 7: Cloud-Specific Risk Analysis - Multi-tenancy, shared responsibility, and cloud misconfigurations."""
        for component in architecture.components:
            comp_type_lower = component.type.lower()
            comp_name_lower = component.name.lower()
            
            # Cloud storage
            if any(keyword in comp_type_lower or keyword in comp_name_lower for keyword in ["s3", "blob", "bucket", "storage", "gcs", "azure"]):
                description = (
                    f"[PASTA Stage 7] Cloud storage misconfiguration risk for '{component.name}': "
                    "Publicly accessible buckets/containers expose sensitive data through misconfigured ACLs, "
                    "public read permissions, or disabled encryption, leading to data breaches and compliance violations."
                )
                yield self._threat(
                    component.name,
                    description,
                    StrideCategory.INFORMATION_DISCLOSURE,
                    "Enable block public access by default, enforce bucket policies, enable versioning and MFA delete, "
                    "implement automated compliance scanning (AWS Config, Azure Policy), and use private endpoints.",
                    stage=7,
                    stage_title="Cloud Risk & Impact Analysis",
                    severity="high",
                    sensitive=True,
                    attack_tactic=ATTACK_TACTICS["collection"],
                )
            
            # Serverless functions
            if any(keyword in comp_type_lower or keyword in comp_name_lower for keyword in ["lambda", "function", "serverless", "faas"]):
                description = (
                    f"[PASTA Stage 7] Serverless function over-permissioned risk for '{component.name}': "
                    "Function has excessive IAM permissions allowing lateral movement to other cloud resources, "
                    "data exfiltration, or privilege escalation beyond intended scope."
                )
                yield self._threat(
                    component.name,
                    description,
                    StrideCategory.ELEVATION_OF_PRIVILEGE,
                    "Apply least-privilege IAM roles, use resource-based policies, implement function isolation, "
                    "enable AWS Lambda runtime protection, and audit permissions regularly.",
                    stage=7,
                    stage_title="Cloud Risk & Impact Analysis",
                    severity="high",
                    sensitive=is_sensitive_component(component),
                    attack_tactic=ATTACK_TACTICS["privilege_escalation"],
                    attack_technique=ATTACK_TECHNIQUES["serverless_execution"],
                )
            
            # Cloud databases
            if any(keyword in comp_type_lower or keyword in comp_name_lower for keyword in ["rds", "dynamodb", "cosmos", "aurora", "cloud"]):
                description = (
                    f"[PASTA Stage 7] Cloud database exposure risk for '{component.name}': "
                    "Publicly accessible database endpoints, weak security groups, or disabled audit logging "
                    "expose sensitive data and violate data residency/compliance requirements."
                )
                yield self._threat(
                    component.name,
                    description,
                    StrideCategory.INFORMATION_DISCLOSURE,
                    "Place databases in private subnets, use VPC endpoints, enable encryption at rest and in transit, "
                    "implement IAM database authentication, enable audit logging, and enforce network ACLs.",
                    stage=7,
                    stage_title="Cloud Risk & Impact Analysis",
                    severity="high",
                    sensitive=True,
                    attack_tactic=ATTACK_TACTICS["collection"],
                )

    def _step7_risk_analysis(self, architecture: ArchitectureModel) -> Iterable[Threat]:
        """PASTA Stage 7: Residual Risk & Impact Analysis - Assess business impact and operational risks."""
        for flow in architecture.data_flows:
            if not flow.description:
                continue
            desc_lower = flow.description.lower()
            
            # Business-critical batch/analytics flows
            if any(keyword in desc_lower for keyword in ("batch", "etl", "job", "sync", "pipeline", "analytics")):
                description = (
                    f"[PASTA Stage 7] Business impact analysis: Disruption to operational flow '{flow.description}' "
                    f"({flow.source}→{flow.destination}) could cause downstream impact to decisioning, reporting, "
                    "compliance, or customer-facing services, creating operational and financial risk."
                )
                yield self._threat(
                    f"{flow.source}->{flow.destination}",
                    description,
                    StrideCategory.DENIAL_OF_SERVICE,
                    "Introduce resiliency patterns: retries with exponential backoff, circuit breakers, message queues, "
                    "resource quotas, SLA monitoring, and disaster recovery procedures for analytics workloads.",
                    stage=7,
                    stage_title="Residual Risk & Impact Analysis",
                    severity="medium",
                    sensitive=flow.sensitive,
                    attack_tactic=ATTACK_TACTICS["impact"],
                )
            
            # Payment/financial flows
            if any(keyword in desc_lower for keyword in ("payment", "transaction", "billing", "invoice", "pci")):
                description = (
                    f"[PASTA Stage 7] Financial risk: Compromise of payment flow '{flow.description}' "
                    "could result in financial fraud, PCI-DSS non-compliance penalties, reputational damage, "
                    "and customer trust erosion."
                )
                yield self._threat(
                    f"{flow.source}->{flow.destination}",
                    description,
                    StrideCategory.TAMPERING,
                    "Implement PCI-DSS controls: end-to-end encryption, tokenization, fraud detection, "
                    "transaction integrity verification, and security monitoring with alerting.",
                    stage=7,
                    stage_title="Residual Risk & Impact Analysis",
                    severity="high",
                    sensitive=True,
                    attack_tactic=ATTACK_TACTICS["impact"],
                )
            
            # User authentication/identity flows
            if any(keyword in desc_lower for keyword in ("login", "auth", "identity", "credential", "sso")):
                description = (
                    f"[PASTA Stage 7] Compliance & privacy risk: Failure in authentication flow '{flow.description}' "
                    "may violate access control policies, create audit failures, enable unauthorized access, "
                    "and trigger regulatory non-compliance (SOC2, ISO 27001)."
                )
                yield self._threat(
                    f"{flow.source}->{flow.destination}",
                    description,
                    StrideCategory.SPOOFING,
                    "Enforce strong authentication (MFA, passwordless), continuous authentication/authorization, "
                    "comprehensive audit logging, and regular compliance assessments.",
                    stage=7,
                    stage_title="Residual Risk & Impact Analysis",
                    severity="high",
                    sensitive=True,
                    attack_tactic=ATTACK_TACTICS["credential_access"],
                )
        
        # Component-level business impact
        for component in architecture.components:
            comp_type_lower = component.type.lower()
            
            # Single points of failure
            if comp_type_lower in {"database", "storage", "queue", "cache"} and is_sensitive_component(component):
                description = (
                    f"[PASTA Stage 7] Availability risk: '{component.name}' represents potential single point of failure; "
                    "outage or compromise could halt critical business operations, violate SLA commitments, "
                    "and impact customer experience."
                )
                yield self._threat(
                    component.name,
                    description,
                    StrideCategory.DENIAL_OF_SERVICE,
                    "Deploy high-availability architecture: active-active/active-passive clustering, automated failover, "
                    "geographic redundancy, and tested disaster recovery procedures.",
                    stage=7,
                    stage_title="Residual Risk & Impact Analysis",
                    severity="high",
                    sensitive=True,
                    attack_tactic=ATTACK_TACTICS["impact"],
                )

    def _threat(
        self,
        component: str,
        description: str,
        category: StrideCategory,
        mitigation: str,
        *,
        stage: int,
        stage_title: str,
        severity: str,
        sensitive: bool,
        attack_tactic: str = "",
        attack_technique: str = "",
    ) -> Threat:
        dread = self._score(severity=severity, sensitive=sensitive)
        methodology = f"PASTA Step {stage}: {stage_title}"
        references = []
        if attack_tactic:
            references.append(f"MITRE ATT&CK Tactic: {attack_tactic}")
        if attack_technique:
            references.append(f"MITRE ATT&CK Technique: {attack_technique}")
        return Threat(
            component=component,
            threat=description,
            stride_category=category,
            dread=dread,
            mitigation=mitigation,
            methodology=methodology,
            references=tuple(references),
        )

    def _score(self, *, severity: str, sensitive: bool) -> DreadScore:
        base_map = {"low": 4, "medium": 6, "high": 8}
        base = base_map.get(severity, 6)
        if sensitive:
            base = min(9, base + 1)
        damage = min(10, base + (1 if severity == "high" else 0))
        reproducibility = min(10, base)
        exploitability = min(10, base + (1 if severity != "low" else 0))
        affected_users = min(10, base + (1 if severity == "high" else 0))
        discoverability = min(10, base - 1 if base > 5 else base)
        return DreadScore(
            damage=damage,
            reproducibility=reproducibility,
            exploitability=exploitability,
            affected_users=affected_users,
            discoverability=discoverability,
        )

    def _trust_zone_lookup(self, architecture: ArchitectureModel) -> dict[str, str]:
        lookup: dict[str, str] = {}
        for boundary in architecture.trust_boundaries:
            for component_name in boundary.components:
                lookup[component_name] = boundary.name
        return lookup