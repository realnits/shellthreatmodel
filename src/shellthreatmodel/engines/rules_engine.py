"""Deterministic STRIDE/DREAD rules engine with OWASP Top 10 and CWE mapping."""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from shellthreatmodel.models.architecture import ArchitectureModel, Component, DataFlow
from shellthreatmodel.models.threat import DreadScore, StrideCategory, Threat
from shellthreatmodel.engines.base import (
    ThreatEngine,
    is_sensitive_component,
    is_public_facing,
    is_privileged_component,
    is_cloud_component,
)


# OWASP Top 10 mapping (year-agnostic labels; keeps the ruleset future-friendly)
OWASP_MAPPING = {
    "broken_access_control": "A01 - Broken Access Control",
    "cryptographic_failures": "A02 - Cryptographic Failures",
    "injection": "A03 - Injection",
    "insecure_design": "A04 - Insecure Design",
    "security_misconfiguration": "A05 - Security Misconfiguration",
    "vulnerable_components": "A06 - Vulnerable and Outdated Components",
    "authentication_failures": "A07 - Identification and Authentication Failures",
    "data_integrity_failures": "A08 - Software and Data Integrity Failures",
    "logging_failures": "A09 - Security Logging and Monitoring Failures",
    "ssrf": "A10 - Server-Side Request Forgery (SSRF)",
}

# OWASP API Security Top 10 mapping
OWASP_API_MAPPING = {
    "broken_object_level_auth": "API1 - Broken Object Level Authorization (BOLA)",
    "broken_authentication": "API2 - Broken Authentication",
    "broken_object_property_level_auth": "API3 - Broken Object Property Level Authorization",
    "unrestricted_resource_consumption": "API4 - Unrestricted Resource Consumption",
    "broken_function_level_auth": "API5 - Broken Function Level Authorization",
    "unrestricted_access_to_sensitive_flows": "API6 - Unrestricted Access to Sensitive Business Flows",
    "server_side_request_forgery": "API7 - Server Side Request Forgery (SSRF)",
    "security_misconfiguration": "API8 - Security Misconfiguration",
    "improper_inventory_management": "API9 - Improper Inventory Management",
    "unsafe_consumption_of_apis": "API10 - Unsafe Consumption of APIs",
}

# NIST Cybersecurity Framework mapping
NIST_CSF_MAPPING = {
    "identify": "ID",
    "protect": "PR",
    "detect": "DE",
    "respond": "RS",
    "recover": "RC",
}


class RulesThreatEngine(ThreatEngine):
    """Advanced rule-based STRIDE/DREAD threat generator with industry mappings."""

    name = "rules"

    def __init__(self, base_score: int = 6) -> None:
        self.base_score = base_score

    def generate(self, architecture: ArchitectureModel) -> Iterable[Threat]:
        component_threats = list(self._component_threats(architecture))
        flow_threats = list(self._flow_threats(architecture))
        crypto_threats = list(self._cryptography_threats(architecture))
        auth_threats = list(self._authentication_threats(architecture))
        api_threats = list(self._api_security_threats(architecture))
        owasp_2025_threats = list(self._owasp_2025_threats(architecture))
        llm_threats = list(self._llm_application_threats(architecture))
        cloud_threats = list(self._cloud_native_threats(architecture))
        zero_trust_threats = list(self._zero_trust_threats(architecture))
        return (
            component_threats
            + flow_threats
            + crypto_threats
            + auth_threats
            + api_threats
            + owasp_2025_threats
            + llm_threats
            + cloud_threats
            + zero_trust_threats
        )

    def _owasp_2025_threats(self, architecture: ArchitectureModel) -> Iterable[Threat]:
        """Generate additional OWASP-aligned threats (modern appsec / 2025-era focus).

        This intentionally targets areas that are increasingly common in 2024/2025 real-world incidents:
        supply-chain & CI/CD integrity, unsafe defaults/misconfig, and multi-tenant isolation failures.
        """

        for component in architecture.components:
            comp_type_lower = component.type.lower()
            comp_name_lower = component.name.lower()

            is_web_or_api = any(
                keyword in comp_type_lower or keyword in comp_name_lower
                for keyword in ["web", "frontend", "ui", "portal", "api", "rest", "graphql", "service", "app"]
            )

            # Security Misconfiguration: insecure headers / CORS / verbose errors
            if is_web_or_api:
                yield self._threat(
                    component,
                    "Security misconfiguration (missing security headers, unsafe CORS, verbose errors) enabling exploit chaining",
                    StrideCategory.INFORMATION_DISCLOSURE,
                    "Harden defaults: set strict CORS allowlists, disable debug/stack traces in prod, set security headers "
                    "(CSP, HSTS, X-Content-Type-Options, Referrer-Policy), and ensure consistent error handling.",
                    cwe="CWE-16",
                    owasp=OWASP_MAPPING["security_misconfiguration"],
                )

            # Broken Access Control: multi-tenant isolation / authorization gaps
            if any(keyword in comp_name_lower for keyword in ["tenant", "multi-tenant", "org", "workspace", "account"]):
                yield self._threat(
                    component,
                    "Multi-tenant isolation failure causing cross-tenant data access (IDOR / authorization gaps)",
                    StrideCategory.ELEVATION_OF_PRIVILEGE,
                    "Enforce tenant scoping at the data layer, include tenant_id in every query, use row-level security where possible, "
                    "and add authorization tests for cross-tenant access.",
                    high_severity=True,
                    cwe="CWE-639",
                    owasp=OWASP_MAPPING["broken_access_control"],
                )

            # Software & Data Integrity Failures: CI/CD and artifact tampering
            if any(
                keyword in comp_type_lower or keyword in comp_name_lower
                for keyword in ["ci", "cd", "cicd", "pipeline", "build", "jenkins", "github actions", "gitlab", "runner"]
            ):
                yield self._threat(
                    component,
                    "Compromise of CI/CD pipeline leading to artifact tampering or malicious release",
                    StrideCategory.TAMPERING,
                    "Lock down CI/CD: use short-lived credentials (OIDC), protect secrets, require signed commits/releases, "
                    "generate and verify provenance (SLSA), sign artifacts (e.g., Sigstore/cosign), and restrict who can modify pipelines.",
                    high_severity=True,
                    cwe="CWE-353",
                    owasp=OWASP_MAPPING["data_integrity_failures"],
                )
                yield self._threat(
                    component,
                    "Dependency confusion / typosquatting risk from unpinned or unsafe dependency resolution",
                    StrideCategory.TAMPERING,
                    "Pin dependencies, use private registries with namespace controls, enable dependency verification (hash-lock), "
                    "monitor for malicious packages, and maintain an SBOM with automated policy checks.",
                    high_severity=True,
                    cwe="CWE-829",
                    owasp=OWASP_MAPPING["data_integrity_failures"],
                )

            # Vulnerable/Outdated Components: libraries, images, runtime
            if any(keyword in comp_type_lower for keyword in ["library", "dependency", "package", "runtime", "image"]):
                yield self._threat(
                    component,
                    "Vulnerable or outdated third-party components introducing known exploitable weaknesses",
                    StrideCategory.TAMPERING,
                    "Continuously scan dependencies/images, enforce patch SLAs, use minimal base images, and block builds on critical CVEs.",
                    cwe="CWE-1104",
                    owasp=OWASP_MAPPING["vulnerable_components"],
                )

    def _llm_application_threats(self, architecture: ArchitectureModel) -> Iterable[Threat]:
        """Generate LLM application threats (common in 2025-era architectures)."""

        for component in architecture.components:
            comp_type_lower = component.type.lower()
            comp_name_lower = component.name.lower()

            is_llm = any(
                keyword in comp_type_lower or keyword in comp_name_lower
                for keyword in [
                    "llm",
                    "gpt",
                    "openai",
                    "chatbot",
                    "prompt",
                    "agent",
                    "rag",
                    "embedding",
                    "vector",
                    "retrieval",
                    "tool",
                    "plugin",
                ]
            )
            if not is_llm:
                continue

            yield self._threat(
                component,
                "Prompt injection causing policy bypass, sensitive data disclosure, or unsafe tool execution",
                StrideCategory.INFORMATION_DISCLOSURE,
                "Treat prompts as untrusted input: isolate system prompts, implement input/output filtering, restrict tool usage with allowlists, "
                "use least-privilege for tool credentials, and add red-team prompt testing.",
                high_severity=True,
                cwe="CWE-20",
                owasp=OWASP_MAPPING["insecure_design"],
            )
            yield self._threat(
                component,
                "Insecure LLM output handling leading to injection into downstream systems (HTML/SQL/command/template)",
                StrideCategory.TAMPERING,
                "Encode/escape model output for the target sink, avoid direct execution, use structured outputs (JSON schema), "
                "and validate/approve high-risk actions before execution.",
                high_severity=True,
                cwe="CWE-79",
                owasp=OWASP_MAPPING["injection"],
            )
            yield self._threat(
                component,
                "RAG/vector store poisoning causing retrieval of malicious or misleading content",
                StrideCategory.TAMPERING,
                "Apply ingestion controls (authz, moderation), content signing/attestation, isolate tenant indices, "
                "and monitor for anomalous retrieval patterns.",
                high_severity=True,
                cwe="CWE-345",
                owasp=OWASP_MAPPING["data_integrity_failures"],
            )
            yield self._threat(
                component,
                "LLM cost/availability denial-of-service via token explosion or expensive tool calls",
                StrideCategory.DENIAL_OF_SERVICE,
                "Enforce quotas, max tokens, tool-call budgets, caching, and circuit breakers; monitor spend and latency with alerts.",
                cwe="CWE-400",
                owasp=OWASP_MAPPING["security_misconfiguration"],
            )

    def _component_threats(self, architecture: ArchitectureModel) -> Iterable[Threat]:
        for component in architecture.components:
            comp_type = component.type.lower()
            comp_name_lower = component.name.lower()
            
            # Database and storage threats
            if comp_type in {"database", "datastore", "storage", "cache", "redis", "mongodb", "s3"}:
                yield self._threat(
                    component,
                    "Tampering with stored data",
                    StrideCategory.TAMPERING,
                    "Ensure integrity controls (signatures, versioning) and access restrictions on data stores.",
                    sensitivity_boost=True,
                    cwe="CWE-345",
                    owasp=OWASP_MAPPING["data_integrity_failures"],
                )
                yield self._threat(
                    component,
                    "Sensitive data disclosure through inadequate access controls",
                    StrideCategory.INFORMATION_DISCLOSURE,
                    "Encrypt data at rest (AES-256+), enforce least-privilege access, implement data classification tagging.",
                    sensitivity_boost=True,
                    cwe="CWE-311",
                    owasp=OWASP_MAPPING["cryptographic_failures"],
                )
                yield self._threat(
                    component,
                    "SQL/NoSQL injection allowing unauthorized data access",
                    StrideCategory.TAMPERING,
                    "Use parameterized queries, ORM frameworks, and input validation for all database interactions.",
                    high_severity=True,
                    cwe="CWE-89",
                    owasp=OWASP_MAPPING["injection"],
                )
            
            # API and service threats
            if comp_type in {"api", "service", "application", "web", "rest", "graphql", "microservice"}:
                if "log" not in comp_type:
                    yield self._threat(
                        component,
                        "Lack of repudiation evidence for security-relevant actions",
                        StrideCategory.REPUDIATION,
                        "Introduce tamper-proof logging with correlation IDs, user attribution, and retention policies.",
                        cwe="CWE-778",
                        owasp=OWASP_MAPPING["logging_failures"],
                    )
                yield self._threat(
                    component,
                    "Broken authentication allowing unauthorized API access",
                    StrideCategory.SPOOFING,
                    "Implement OAuth 2.0/OIDC, JWT validation, API key rotation, and rate limiting per identity.",
                    high_severity=True,
                    cwe="CWE-287",
                    owasp=OWASP_MAPPING["authentication_failures"],
                )
                yield self._threat(
                    component,
                    "Denial of service through resource exhaustion",
                    StrideCategory.DENIAL_OF_SERVICE,
                    "Apply rate limiting, request size limits, connection pooling, and circuit breakers.",
                    cwe="CWE-400",
                    owasp=OWASP_MAPPING["security_misconfiguration"],
                )
                if "public" in comp_name_lower or "external" in comp_name_lower:
                    yield self._threat(
                        component,
                        "Server-Side Request Forgery (SSRF) from external inputs",
                        StrideCategory.TAMPERING,
                        "Validate and sanitize URLs, use allowlists for destinations, disable unnecessary protocols.",
                        high_severity=True,
                        cwe="CWE-918",
                        owasp=OWASP_MAPPING["ssrf"],
                    )
            
            # Administrative interfaces
            if comp_type in {"admin", "portal", "dashboard"} or "admin" in comp_name_lower:
                yield self._threat(
                    component,
                    "Privilege escalation via administrative interface",
                    StrideCategory.ELEVATION_OF_PRIVILEGE,
                    "Apply role-based access control (RBAC), multi-factor authentication (MFA), and activity monitoring.",
                    high_severity=True,
                    cwe="CWE-269",
                    owasp=OWASP_MAPPING["broken_access_control"],
                )
                yield self._threat(
                    component,
                    "Cross-Site Request Forgery (CSRF) on privileged operations",
                    StrideCategory.TAMPERING,
                    "Implement CSRF tokens, SameSite cookies, and double-submit patterns for state-changing operations.",
                    cwe="CWE-352",
                    owasp=OWASP_MAPPING["broken_access_control"],
                )
            
            # Message queues and event streams
            if comp_type in {"queue", "kafka", "rabbitmq", "sqs", "pubsub", "eventbus"}:
                yield self._threat(
                    component,
                    "Message tampering or replay attacks",
                    StrideCategory.TAMPERING,
                    "Sign messages cryptographically, use nonces/timestamps, and validate message integrity.",
                    sensitivity_boost=True,
                    cwe="CWE-294",
                    owasp=OWASP_MAPPING["data_integrity_failures"],
                )
                yield self._threat(
                    component,
                    "Unauthorized message consumption or publishing",
                    StrideCategory.INFORMATION_DISCLOSURE,
                    "Enforce topic-level ACLs, encrypt message payloads, and audit access patterns.",
                    cwe="CWE-862",
                    owasp=OWASP_MAPPING["broken_access_control"],
                )
            
            # Container and orchestration
            if comp_type in {"container", "docker", "kubernetes", "pod"}:
                yield self._threat(
                    component,
                    "Container escape or privilege escalation",
                    StrideCategory.ELEVATION_OF_PRIVILEGE,
                    "Run containers as non-root, apply security contexts, use Pod Security Standards, scan images.",
                    high_severity=True,
                    cwe="CWE-250",
                    owasp=OWASP_MAPPING["security_misconfiguration"],
                )
                yield self._threat(
                    component,
                    "Vulnerable dependencies in container images",
                    StrideCategory.TAMPERING,
                    "Scan images for CVEs, use minimal base images, automate patching, enforce image signing.",
                    cwe="CWE-1104",
                    owasp=OWASP_MAPPING["vulnerable_components"],
                )

    def _flow_threats(self, architecture: ArchitectureModel) -> Iterable[Threat]:
        trust_lookup = self._trust_zone_lookup(architecture)
        for flow in architecture.data_flows:
            protocol_lower = (flow.protocol or "").lower()
            
            # Unencrypted transport threats
            if protocol_lower in {"http", "tcp", "ftp", "telnet", "smtp"} and flow.sensitive:
                yield self._flow_threat(
                    flow,
                    "Sensitive data transmitted without transport protection (cleartext protocol)",
                    StrideCategory.INFORMATION_DISCLOSURE,
                    "Enforce TLS 1.2+ with strong cipher suites, certificate pinning, and HSTS headers.",
                    sensitivity_boost=True,
                    cwe="CWE-319",
                    owasp=OWASP_MAPPING["cryptographic_failures"],
                )
            
            # Cross-boundary communication
            if self._crosses_boundary(flow, trust_lookup):
                yield self._flow_threat(
                    flow,
                    "Unauthenticated cross-boundary communication allowing spoofing",
                    StrideCategory.SPOOFING,
                    "Add mutual TLS (mTLS), service mesh authentication, and network segmentation policies.",
                    cwe="CWE-306",
                    owasp=OWASP_MAPPING["authentication_failures"],
                )
                yield self._flow_threat(
                    flow,
                    "Insufficient network segmentation allowing lateral movement",
                    StrideCategory.ELEVATION_OF_PRIVILEGE,
                    "Implement zero-trust networking, microsegmentation, and least-privilege firewall rules.",
                    high_severity=True,
                    cwe="CWE-668",
                    owasp=OWASP_MAPPING["broken_access_control"],
                )
            
            # Authentication flow threats
            if flow.description and "health" not in flow.description.lower():
                desc_lower = flow.description.lower()
                if any(keyword in desc_lower for keyword in ["login", "auth", "token", "credential", "password"]):
                    yield self._flow_threat(
                        flow,
                        "Credential replay, brute-force, or stuffing attacks on authentication flow",
                        StrideCategory.SPOOFING,
                        "Add rate limiting, CAPTCHA, account lockout, anomaly detection, and MFA enforcement.",
                        high_severity=True,
                        cwe="CWE-307",
                        owasp=OWASP_MAPPING["authentication_failures"],
                    )
                
                # Batch and scheduled operations
                if any(keyword in desc_lower for keyword in ["batch", "sync", "cron", "etl", "pipeline"]):
                    yield self._flow_threat(
                        flow,
                        "Resource exhaustion through scheduled operations or batch processing",
                        StrideCategory.DENIAL_OF_SERVICE,
                        "Add capacity planning, circuit breakers, backpressure controls, and job throttling.",
                        cwe="CWE-400",
                        owasp=OWASP_MAPPING["security_misconfiguration"],
                    )
                
                # File upload flows
                if any(keyword in desc_lower for keyword in ["upload", "file", "attachment", "document"]):
                    yield self._flow_threat(
                        flow,
                        "Malicious file upload allowing code execution or stored XSS",
                        StrideCategory.TAMPERING,
                        "Validate file types, scan for malware, sanitize filenames, store outside webroot, use CDN.",
                        high_severity=True,
                        cwe="CWE-434",
                        owasp=OWASP_MAPPING["broken_access_control"],
                    )
            
            # Protocol-specific threats
            if protocol_lower == "grpc":
                yield self._flow_threat(
                    flow,
                    "gRPC reflection exposing service metadata to attackers",
                    StrideCategory.INFORMATION_DISCLOSURE,
                    "Disable gRPC reflection in production, use authentication, and implement request validation.",
                    cwe="CWE-200",
                    owasp=OWASP_MAPPING["security_misconfiguration"],
                )
            
            if protocol_lower in {"ws", "websocket", "wss"}:
                yield self._flow_threat(
                    flow,
                    "WebSocket connection hijacking or message injection",
                    StrideCategory.SPOOFING,
                    "Validate WebSocket origin, use secure WebSocket (WSS), implement message signing.",
                    cwe="CWE-346",
                    owasp=OWASP_MAPPING["broken_access_control"],
                )

    def _crosses_boundary(self, flow: DataFlow, trust_lookup: dict[str, str]) -> bool:
        return trust_lookup.get(flow.source) != trust_lookup.get(flow.destination)

    def _cryptography_threats(self, architecture: ArchitectureModel) -> Iterable[Threat]:
        """Generate cryptography-specific threats."""
        for component in architecture.components:
            comp_type_lower = component.type.lower()
            comp_name_lower = component.name.lower()
            
            # Key management components
            if any(keyword in comp_type_lower or keyword in comp_name_lower for keyword in ["vault", "kms", "hsm", "key", "secret"]):
                yield self._threat(
                    component,
                    "Cryptographic key exposure through inadequate protection",
                    StrideCategory.INFORMATION_DISCLOSURE,
                    "Use hardware security modules (HSM), key rotation policies, and envelope encryption.",
                    high_severity=True,
                    cwe="CWE-320",
                    owasp=OWASP_MAPPING["cryptographic_failures"],
                )
                yield self._threat(
                    component,
                    "Weak key derivation functions allowing brute-force attacks",
                    StrideCategory.SPOOFING,
                    "Use PBKDF2, bcrypt, or Argon2 with high work factors; avoid MD5, SHA1 for passwords.",
                    cwe="CWE-916",
                    owasp=OWASP_MAPPING["cryptographic_failures"],
                )
        
        for flow in architecture.data_flows:
            if flow.sensitive and flow.protocol:
                protocol_lower = flow.protocol.lower()
                if protocol_lower in {"https", "tls", "ssl"}:
                    yield self._flow_threat(
                        flow,
                        "Downgrade attacks or weak cipher suites allowing traffic decryption",
                        StrideCategory.INFORMATION_DISCLOSURE,
                        "Enforce TLS 1.2+, disable SSLv3/TLS1.0/1.1, use Forward Secrecy, prefer AEAD ciphers.",
                        sensitivity_boost=True,
                        cwe="CWE-757",
                        owasp=OWASP_MAPPING["cryptographic_failures"],
                    )

    def _authentication_threats(self, architecture: ArchitectureModel) -> Iterable[Threat]:
        """Generate authentication and session management threats."""
        for component in architecture.components:
            comp_type_lower = component.type.lower()
            comp_name_lower = component.name.lower()
            
            # Identity and auth services
            if any(keyword in comp_type_lower or keyword in comp_name_lower for keyword in ["auth", "sso", "idp", "oauth", "saml", "ldap", "ad"]):
                yield self._threat(
                    component,
                    "Session fixation or hijacking attacks",
                    StrideCategory.SPOOFING,
                    "Regenerate session IDs after authentication, use HTTPOnly/Secure flags, implement session timeouts.",
                    high_severity=True,
                    cwe="CWE-384",
                    owasp=OWASP_MAPPING["authentication_failures"],
                )
                yield self._threat(
                    component,
                    "Insecure password storage allowing credential theft",
                    StrideCategory.INFORMATION_DISCLOSURE,
                    "Hash passwords with Argon2id/bcrypt, add unique salts, enforce strong password policies.",
                    high_severity=True,
                    cwe="CWE-256",
                    owasp=OWASP_MAPPING["cryptographic_failures"],
                )
                yield self._threat(
                    component,
                    "Missing or broken multi-factor authentication (MFA)",
                    StrideCategory.SPOOFING,
                    "Enforce MFA for all privileged accounts, use TOTP/FIDO2, protect MFA bypass workflows.",
                    cwe="CWE-308",
                    owasp=OWASP_MAPPING["authentication_failures"],
                )

    def _api_security_threats(self, architecture: ArchitectureModel) -> Iterable[Threat]:
        """Generate OWASP API Security Top 10 threats for API components."""
        for component in architecture.components:
            comp_type_lower = component.type.lower()
            comp_name_lower = component.name.lower()
            
            # REST, GraphQL, gRPC APIs
            if any(keyword in comp_type_lower or keyword in comp_name_lower for keyword in ["api", "rest", "graphql", "grpc"]):
                # API1:2023 - Broken Object Level Authorization
                yield self._threat(
                    component,
                    "Broken Object Level Authorization (BOLA/IDOR) allowing unauthorized access to resources",
                    StrideCategory.ELEVATION_OF_PRIVILEGE,
                    "Implement object-level access control checks, validate user ownership, use UUIDs instead of sequential IDs, "
                    "enforce authorization at the data layer, and implement comprehensive authorization testing.",
                    high_severity=True,
                    cwe="CWE-639",
                    owasp=OWASP_API_MAPPING["broken_object_level_auth"],
                )
                
                # API3:2023 - Broken Object Property Level Authorization
                yield self._threat(
                    component,
                    "Mass assignment vulnerabilities exposing or modifying sensitive object properties",
                    StrideCategory.TAMPERING,
                    "Use allow-lists for property binding, implement DTO patterns, validate property-level permissions, "
                    "separate read/write models, and avoid direct object binding from requests.",
                    high_severity=True,
                    cwe="CWE-915",
                    owasp=OWASP_API_MAPPING["broken_object_property_level_auth"],
                )
                
                # API4:2023 - Unrestricted Resource Consumption
                yield self._threat(
                    component,
                    "API resource exhaustion through pagination abuse, query complexity, or excessive requests",
                    StrideCategory.DENIAL_OF_SERVICE,
                    "Implement rate limiting per endpoint, enforce pagination limits, limit query depth/complexity, "
                    "use query cost analysis (GraphQL), implement timeout policies, and monitor resource consumption.",
                    cwe="CWE-770",
                    owasp=OWASP_API_MAPPING["unrestricted_resource_consumption"],
                )
                
                # API5:2023 - Broken Function Level Authorization
                yield self._threat(
                    component,
                    "Broken Function Level Authorization allowing access to administrative functions",
                    StrideCategory.ELEVATION_OF_PRIVILEGE,
                    "Implement role-based access control (RBAC), deny by default, enforce authorization on all endpoints, "
                    "avoid relying on client-side checks, and implement centralized authorization logic.",
                    high_severity=True,
                    cwe="CWE-285",
                    owasp=OWASP_API_MAPPING["broken_function_level_auth"],
                )
                
                # API9:2023 - Improper Inventory Management
                yield self._threat(
                    component,
                    "Exposed API endpoints (debug, deprecated, shadow APIs) increasing attack surface",
                    StrideCategory.INFORMATION_DISCLOSURE,
                    "Maintain API inventory with version tracking, disable debug endpoints in production, "
                    "implement API gateway discovery, deprecate old versions properly, and use API documentation as code.",
                    cwe="CWE-1059",
                    owasp=OWASP_API_MAPPING["improper_inventory_management"],
                )
            
            # GraphQL-specific threats
            if "graphql" in comp_type_lower or "graphql" in comp_name_lower:
                yield self._threat(
                    component,
                    "GraphQL introspection exposing schema details to attackers",
                    StrideCategory.INFORMATION_DISCLOSURE,
                    "Disable introspection in production, implement field-level authorization, use persisted queries, "
                    "and monitor query complexity to prevent information disclosure.",
                    cwe="CWE-612",
                    owasp=OWASP_API_MAPPING["security_misconfiguration"],
                )
                
                yield self._threat(
                    component,
                    "GraphQL batching attacks amplifying resource consumption",
                    StrideCategory.DENIAL_OF_SERVICE,
                    "Limit batch query size, implement query cost analysis, enforce depth limiting, "
                    "and use query complexity budgets to prevent resource exhaustion.",
                    cwe="CWE-400",
                    owasp=OWASP_API_MAPPING["unrestricted_resource_consumption"],
                )

    def _cloud_native_threats(self, architecture: ArchitectureModel) -> Iterable[Threat]:
        """Generate cloud-native and containerized application threats."""
        for component in architecture.components:
            comp_type_lower = component.type.lower()
            comp_name_lower = component.name.lower()
            
            # Kubernetes and orchestration
            if any(keyword in comp_type_lower or keyword in comp_name_lower for keyword in ["kubernetes", "k8s", "pod", "deployment"]):
                yield self._threat(
                    component,
                    "Kubernetes RBAC misconfiguration granting excessive cluster permissions",
                    StrideCategory.ELEVATION_OF_PRIVILEGE,
                    "Apply least-privilege RBAC, use namespaces for isolation, implement Pod Security Standards, "
                    "disable automountServiceAccountToken, and regularly audit RBAC policies.",
                    high_severity=True,
                    cwe="CWE-269",
                    owasp=OWASP_MAPPING["broken_access_control"],
                )
                
                yield self._threat(
                    component,
                    "Exposed Kubernetes API server or dashboard without authentication",
                    StrideCategory.SPOOFING,
                    "Disable anonymous access, use strong authentication (OIDC), implement network policies, "
                    "restrict API server access, and enable audit logging.",
                    high_severity=True,
                    cwe="CWE-306",
                    owasp=OWASP_MAPPING["authentication_failures"],
                )
                
                yield self._threat(
                    component,
                    "Secrets exposed in environment variables or ConfigMaps",
                    StrideCategory.INFORMATION_DISCLOSURE,
                    "Use Kubernetes Secrets with encryption at rest, external secret management (Vault, AWS Secrets Manager), "
                    "avoid hardcoded secrets, implement secret rotation, and use CSI secret store drivers.",
                    high_severity=True,
                    cwe="CWE-798",
                    owasp=OWASP_MAPPING["cryptographic_failures"],
                )
            
            # Service mesh
            if any(keyword in comp_type_lower or keyword in comp_name_lower for keyword in ["istio", "linkerd", "mesh", "envoy"]):
                yield self._threat(
                    component,
                    "Service mesh misconfiguration bypassing mTLS or authorization policies",
                    StrideCategory.SPOOFING,
                    "Enforce strict mTLS mode, implement fine-grained authorization policies, "
                    "enable telemetry and audit logging, and validate service mesh configuration.",
                    cwe="CWE-295",
                    owasp=OWASP_MAPPING["security_misconfiguration"],
                )
            
            # Serverless functions
            if any(keyword in comp_type_lower or keyword in comp_name_lower for keyword in ["lambda", "function", "serverless", "faas", "azure-function"]):
                yield self._threat(
                    component,
                    "Serverless function injection through event data manipulation",
                    StrideCategory.TAMPERING,
                    "Validate and sanitize all event inputs, use input schemas, implement least-privilege execution roles, "
                    "enable runtime protection, and monitor function behavior for anomalies.",
                    high_severity=True,
                    cwe="CWE-74",
                    owasp=OWASP_MAPPING["injection"],
                )
                
                yield self._threat(
                    component,
                    "Over-privileged serverless execution role accessing unintended resources",
                    StrideCategory.ELEVATION_OF_PRIVILEGE,
                    "Apply least-privilege IAM policies, use resource-based policies, implement permission boundaries, "
                    "regularly audit permissions with access analyzer, and document required permissions.",
                    high_severity=True,
                    cwe="CWE-250",
                    owasp=OWASP_MAPPING["broken_access_control"],
                )
                
                yield self._threat(
                    component,
                    "Serverless cold start timing attacks revealing execution patterns",
                    StrideCategory.INFORMATION_DISCLOSURE,
                    "Implement provisioned concurrency, use constant-time operations for security checks, "
                    "avoid timing-dependent logic, and implement proper error handling.",
                    cwe="CWE-208",
                    owasp=OWASP_MAPPING["insecure_design"],
                )
            
            # Cloud storage
            if any(keyword in comp_type_lower or keyword in comp_name_lower for keyword in ["s3", "blob", "bucket", "gcs"]):
                yield self._threat(
                    component,
                    "Public bucket exposure through misconfigured access policies",
                    StrideCategory.INFORMATION_DISCLOSURE,
                    "Enable block public access settings, implement bucket policies with least privilege, "
                    "enable versioning and MFA delete, use CloudTrail/logging, and regularly audit permissions.",
                    high_severity=True,
                    cwe="CWE-732",
                    owasp=OWASP_MAPPING["security_misconfiguration"],
                )
                
                yield self._threat(
                    component,
                    "Server-side encryption not enabled exposing data at rest",
                    StrideCategory.INFORMATION_DISCLOSURE,
                    "Enable default encryption (AES-256 or KMS), use customer-managed keys, "
                    "enforce encryption in bucket policies, and monitor encryption status.",
                    sensitivity_boost=True,
                    cwe="CWE-311",
                    owasp=OWASP_MAPPING["cryptographic_failures"],
                )

    def _zero_trust_threats(self, architecture: ArchitectureModel) -> Iterable[Threat]:
        """Generate zero-trust architecture and micro-segmentation threats."""
        trust_lookup = self._trust_zone_lookup(architecture)
        
        # Analyze cross-zone communications for zero-trust violations
        zone_counts: dict[str, int] = defaultdict(int)
        for flow in architecture.data_flows:
            source_zone = trust_lookup.get(flow.source, "")
            dest_zone = trust_lookup.get(flow.destination, "")
            if source_zone and dest_zone and source_zone != dest_zone:
                zone_counts[f"{source_zone}->{dest_zone}"] += 1
        
        # Detect potential lateral movement paths
        for zone_pair, count in zone_counts.items():
            if count > 5:  # High connectivity between zones
                description = (
                    f"High connectivity between trust zones '{zone_pair}' ({count} flows) "
                    "violates zero-trust principles and increases lateral movement risk if one zone is compromised."
                )
                # Extract zone names
                zones = zone_pair.split("->")
                yield Threat(
                    component=zone_pair,
                    threat=description,
                    stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
                    dread=self._score(zone_pair, StrideCategory.ELEVATION_OF_PRIVILEGE, high_severity=True),
                    mitigation="Implement microsegmentation with network policies, enforce explicit authorization for cross-zone traffic, "
                    "deploy service mesh with mTLS, implement zero-trust network access (ZTNA), and minimize cross-zone dependencies.",
                    references=(f"NIST CSF: {NIST_CSF_MAPPING['protect']}.AC-4",),
                )
        
        # Check for components without trust boundary assignment
        for component in architecture.components:
            if component.name not in trust_lookup:
                description = (
                    f"Component '{component.name}' not assigned to trust boundary, "
                    "making it difficult to enforce zone-based access controls and violating zero-trust architecture principles."
                )
                yield self._threat(
                    component,
                    description,
                    StrideCategory.ELEVATION_OF_PRIVILEGE,
                    "Assign all components to appropriate trust zones, implement network segmentation, "
                    "define and enforce zone-to-zone communication policies, and document trust boundaries.",
                    cwe="CWE-1008",
                    owasp=OWASP_MAPPING["insecure_design"],
                )

    def _authentication_threats(self, architecture: ArchitectureModel) -> Iterable[Threat]:
        """Generate authentication and session management threats."""
        for component in architecture.components:
            comp_type_lower = component.type.lower()
            comp_name_lower = component.name.lower()
            
            # Identity and auth services
            if any(keyword in comp_type_lower or keyword in comp_name_lower for keyword in ["auth", "sso", "idp", "oauth", "saml", "ldap", "ad"]):
                yield self._threat(
                    component,
                    "Session fixation or hijacking attacks",
                    StrideCategory.SPOOFING,
                    "Regenerate session IDs after authentication, use HTTPOnly/Secure flags, implement session timeouts.",
                    high_severity=True,
                    cwe="CWE-384",
                    owasp=OWASP_MAPPING["authentication_failures"],
                )
                yield self._threat(
                    component,
                    "Insecure password storage allowing credential theft",
                    StrideCategory.INFORMATION_DISCLOSURE,
                    "Hash passwords with Argon2id/bcrypt, add unique salts, enforce strong password policies.",
                    high_severity=True,
                    cwe="CWE-256",
                    owasp=OWASP_MAPPING["cryptographic_failures"],
                )
                yield self._threat(
                    component,
                    "Missing or broken multi-factor authentication (MFA)",
                    StrideCategory.SPOOFING,
                    "Enforce MFA for all privileged accounts, use TOTP/FIDO2, protect MFA bypass workflows.",
                    cwe="CWE-308",
                    owasp=OWASP_MAPPING["authentication_failures"],
                )


    def _threat(
        self,
        component: Component,
        description: str,
        category: StrideCategory,
        mitigation: str,
        *,
        sensitivity_boost: bool = False,
        high_severity: bool = False,
        cwe: str = "",
        owasp: str = "",
    ) -> Threat:
        dread = self._score(component.name, category, sensitivity_boost=sensitivity_boost, high_severity=high_severity)
        references = []
        if cwe:
            references.append(f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html")
        if owasp:
            if owasp.startswith("API"):
                references.append(f"OWASP API Security Top 10: {owasp}")
            else:
                references.append(f"OWASP Top 10: {owasp}")
        return Threat(
            component=component.name,
            threat=description,
            stride_category=category,
            dread=dread,
            mitigation=mitigation,
            references=tuple(references),
        )

    def _flow_threat(
        self,
        flow: DataFlow,
        description: str,
        category: StrideCategory,
        mitigation: str,
        *,
        sensitivity_boost: bool = False,
        high_severity: bool = False,
        cwe: str = "",
        owasp: str = "",
    ) -> Threat:
        dread = self._score(
            f"{flow.source}->{flow.destination}", category, sensitivity_boost=sensitivity_boost, high_severity=high_severity
        )
        references = []
        if cwe:
            references.append(f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html")
        if owasp:
            if owasp.startswith("API"):
                references.append(f"OWASP API Security Top 10: {owasp}")
            else:
                references.append(f"OWASP Top 10: {owasp}")
        return Threat(
            component=f"{flow.source}->{flow.destination}",
            threat=description,
            stride_category=category,
            dread=dread,
            mitigation=mitigation,
            references=tuple(references),
        )

    def _score(
        self,
        context: str,
        category: StrideCategory,
        *,
        sensitivity_boost: bool = False,
        high_severity: bool = False,
    ) -> DreadScore:
        """Calculate nuanced DREAD scores based on context and threat characteristics."""
        base = self.base_score
        
        # Adjust base score based on threat characteristics
        if sensitivity_boost:
            base = max(base, 7)
        if high_severity:
            base = max(base, 8)
        
        # Context-aware adjustments
        context_lower = context.lower()
        is_public = any(keyword in context_lower for keyword in ["public", "external", "internet", "exposed"])
        is_admin = any(keyword in context_lower for keyword in ["admin", "privileged", "root", "superuser"])
        is_data = any(keyword in context_lower for keyword in ["database", "storage", "vault", "secret"])
        is_cloud = any(keyword in context_lower for keyword in ["aws", "azure", "gcp", "cloud", "s3", "lambda"])
        is_api = any(keyword in context_lower for keyword in ["api", "rest", "graphql", "grpc"])
        is_container = any(keyword in context_lower for keyword in ["container", "kubernetes", "docker", "pod"])
        
        # Damage potential (0-10)
        damage = min(10, base + (2 if high_severity else 0) + (1 if is_data else 0))
        if is_admin:
            damage = min(10, damage + 2)  # Admin compromise has high damage
        if is_cloud:
            damage = min(10, damage + 1)  # Cloud breaches can scale quickly
        
        # Reproducibility (0-10) - how easily can the attack be repeated
        reproducibility = base
        if category in {StrideCategory.SPOOFING, StrideCategory.ELEVATION_OF_PRIVILEGE}:
            reproducibility = min(10, base + 2)  # Auth bypasses are highly reproducible
        if category == StrideCategory.DENIAL_OF_SERVICE:
            reproducibility = min(10, base + 1)  # DoS attacks are easy to repeat
        if is_api:
            reproducibility = min(10, reproducibility + 1)  # API attacks are easily scriptable
        
        # Exploitability (0-10) - technical difficulty
        exploitability = base
        if sensitivity_boost or high_severity:
            exploitability = min(10, base + 1)
        if is_public:
            exploitability = min(10, exploitability + 2)  # External access significantly increases exploitability
        if category == StrideCategory.INFORMATION_DISCLOSURE:
            exploitability = min(10, exploitability + 1)  # Often easier to exploit
        if is_container:
            exploitability = min(10, exploitability + 1)  # Container escapes require skill but are documented
        
        # Affected users (0-10) - scope of impact
        affected_users = base
        if is_public:
            affected_users = min(10, base + 3)  # Public systems affect many users
        if is_admin:
            affected_users = min(10, affected_users + 2)  # Admin compromise affects entire system
        if is_data:
            affected_users = min(10, affected_users + 1)  # Data breaches affect many users
        if is_cloud:
            affected_users = min(10, affected_users + 1)  # Cloud services typically have wide reach
        
        # Discoverability (0-10) - how easy to find the vulnerability
        discoverability = base
        if is_public:
            discoverability = min(10, base + 2)  # External systems are easier to discover
        if is_api:
            discoverability = min(10, discoverability + 1)  # APIs often have documentation/swagger
        if is_cloud:
            discoverability = min(10, discoverability + 1)  # Cloud misconfigurations are scannable
        
        return DreadScore(
            damage=damage,
            reproducibility=reproducibility,
            exploitability=exploitability,
            affected_users=affected_users,
            discoverability=discoverability,
        )
