import asyncio
import js
import sys
from unittest.mock import MagicMock
from pathlib import Path
import micropip
from pyodide.ffi import create_proxy
from js import document, console, window, Uint8Array, File

# Mock graphviz since it's not available in browser
sys.modules["graphviz"] = MagicMock()

# Last-run state for downloads
LAST_ARCHITECTURE = None
LAST_THREATS = None
LAST_ENGINE_NAME = None
LAST_INPUT_BASENAME = None
LAST_REPORT_HTML = None
LAST_REPORT_MD = None
LAST_REPORT_JSON = None


def _download_text(filename: str, text: str, mime: str) -> None:
    blob = js.Blob.new([text], {"type": mime})
    url = js.URL.createObjectURL(blob)
    a = document.createElement("a")
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    a.remove()
    js.URL.revokeObjectURL(url)

async def setup():
    # Install the package without dependency checking (Pyodide has older versions)
    try:
        await micropip.install("./shellthreatmodel-0.1.0-py3-none-any.whl", deps=False)
        console.log("Package installed successfully")
    except Exception as e:
        console.error(f"Failed to install package: {e}")
        results_container = document.getElementById("results-container")
        results_container.classList.remove("hidden")
        document.getElementById("report-content").innerHTML = f"""
            <div class="bg-red-100 border-l-4 border-red-500 text-red-700 p-4" role="alert">
                <p class="font-bold">Error loading application</p>
                <p>{e}</p>
                <p class="text-sm mt-2">Make sure the .whl file is present in the web directory and all dependencies are available.</p>
            </div>
        """
        return

    from shellthreatmodel.engines.pasta_engine import PASTAThreatEngine
    from shellthreatmodel.engines.rules_engine import RulesThreatEngine
    from shellthreatmodel.utils.loader import load_architecture
    from shellthreatmodel.utils.text import slugify
    from shellthreatmodel.report.generator import render_report
    from shellthreatmodel.utils.analysis_io import serialize_analysis
    
    # Re-enable button
    btn = document.getElementById("analyze-btn")
    btn.disabled = False
    btn.querySelector("span").textContent = "Analyze Architecture"

    download_html_btn = document.getElementById("download-html-btn")
    download_md_btn = document.getElementById("download-md-btn")
    download_json_btn = document.getElementById("download-json-btn")

    def download_html(event=None):
        if not LAST_REPORT_HTML:
            window.alert("Run an analysis first to generate a downloadable report.")
            return
        name = LAST_INPUT_BASENAME or "threat_model"
        _download_text(f"{name}_threats.html", LAST_REPORT_HTML, "text/html")

    def download_md(event=None):
        if not LAST_REPORT_MD:
            window.alert("Run an analysis first to generate a downloadable report.")
            return
        name = LAST_INPUT_BASENAME or "threat_model"
        _download_text(f"{name}_threats.md", LAST_REPORT_MD, "text/markdown")

    def download_json(event=None):
        if not LAST_REPORT_JSON:
            window.alert("Run an analysis first to generate a downloadable report.")
            return
        name = LAST_INPUT_BASENAME or "threat_model"
        _download_text(f"{name}_threats.json", LAST_REPORT_JSON, "application/json")

    async def run_analysis(event):
        global LAST_ARCHITECTURE, LAST_THREATS, LAST_ENGINE_NAME, LAST_INPUT_BASENAME, LAST_REPORT_HTML, LAST_REPORT_MD, LAST_REPORT_JSON

        # UI State
        btn = document.getElementById("analyze-btn")
        spinner = document.getElementById("spinner")
        results_container = document.getElementById("results-container")
        report_content = document.getElementById("report-content")
        
        btn.disabled = True
        spinner.style.display = "inline-block"
        results_container.classList.add("hidden")
        
        try:
            # Get file
            file_input = document.getElementById("file-upload")
            if not file_input.files.length:
                window.alert("Please select a file first.")
                return

            file_obj = file_input.files.item(0)
            file_name = file_obj.name
            input_basename = slugify(file_name.rsplit(".", 1)[0], default="architecture")
            file_ext = file_name.rsplit(".", 1)[-1].lower()
            
            # Read file content
            array_buffer = await file_obj.arrayBuffer()
            uint8_view = Uint8Array.new(array_buffer)
            content_bytes = bytes(uint8_view)
            
            # Write to virtual FS
            input_path = Path(f"/tmp/{file_name}")
            input_path.write_bytes(content_bytes)
            
            # Load Architecture
            console.log(f"Loading architecture from {input_path}")
            architecture = load_architecture(input_path)
            
            # Select Engine
            engine_type = document.getElementById("engine-select").value
            if engine_type == "pasta":
                engine = PASTAThreatEngine()
            else:
                engine = RulesThreatEngine()
            
            # Generate Threats
            console.log(f"Generating threats using {engine.name} engine")
            threats = list(engine.generate(architecture))
            
            # Generate HTML report for browser display
            html_output = generate_html_report(architecture, threats, engine.name)

            # Generate downloadable reports (self-contained)
            title = architecture.title or "Threat Model"
            try:
                html_path = render_report(
                    architecture,
                    threats,
                    "html",
                    title=title,
                    output_path=Path("/tmp/report.html"),
                )
                md_path = render_report(
                    architecture,
                    threats,
                    "markdown",
                    title=title,
                    output_path=Path("/tmp/report.md"),
                )
                LAST_REPORT_HTML = html_path.read_text(encoding="utf-8")
                LAST_REPORT_MD = md_path.read_text(encoding="utf-8")
            except Exception as e:
                console.warn(f"Download report template render failed; using fallback: {e}")
                LAST_REPORT_HTML = "<!doctype html><html><head><meta charset='utf-8'><title>Threat Model</title></head><body>" + html_output + "</body></html>"
                LAST_REPORT_MD = f"# {title}\n\n(Unable to render markdown template in browser.)"

            LAST_REPORT_JSON = serialize_analysis(title, architecture, threats)
            LAST_ARCHITECTURE = architecture
            LAST_THREATS = threats
            LAST_ENGINE_NAME = engine.name
            LAST_INPUT_BASENAME = input_basename
            
            report_content.innerHTML = html_output
            results_container.classList.remove("hidden")

            download_html_btn.disabled = False
            download_md_btn.disabled = False
            download_json_btn.disabled = False
            
        except Exception as e:
            console.error(e)
            window.alert(f"An error occurred: {str(e)}")
        finally:
            btn.disabled = False
            spinner.style.display = "none"

    def generate_html_report(architecture, threats, engine_name):
        # Enhanced HTML generator with detailed reporting and great readability
        
        # Calculate statistics
        threat_list = list(threats)
        total_threats = len(threat_list)
        
        # Count by severity
        high_risk = sum(1 for t in threat_list if t.dread.average() >= 7.5)
        medium_risk = sum(1 for t in threat_list if 5.0 <= t.dread.average() < 7.5)
        low_risk = sum(1 for t in threat_list if t.dread.average() < 5.0)
        
        # Count by STRIDE category
        stride_counts = {}
        for t in threat_list:
            cat = t.stride_category.value
            stride_counts[cat] = stride_counts.get(cat, 0) + 1
        
        # Get unique components
        components = set(t.component for t in threat_list)
        
        # --- Architecture overview helpers ---
        trust_lookup = {}
        for boundary in (architecture.trust_boundaries or []):
            for comp_name in (boundary.components or []):
                trust_lookup[comp_name] = boundary.name

        component_names = set(c.name for c in (architecture.components or []))

        insecure_protocols = {"http", "tcp", "ftp", "telnet", "smtp"}
        findings = []

        if not (architecture.trust_boundaries or []):
            findings.append({
                "severity": "Medium",
                "title": "No trust boundaries defined",
                "details": "Add trust zones to reason about cross-boundary controls and lateral movement.",
                "items": [],
            })

        unzoned = [c.name for c in (architecture.components or []) if c.name not in trust_lookup]
        if unzoned:
            findings.append({
                "severity": "Medium",
                "title": "Components not assigned to a trust boundary",
                "details": "Assign every component to a trust zone to make cross-boundary flows explicit.",
                "items": unzoned,
            })

        unspecified = [c.name for c in (architecture.components or []) if (c.type or "").lower() in {"", "unspecified"}]
        if unspecified:
            findings.append({
                "severity": "Low",
                "title": "Components with unspecified type",
                "details": "Component type drives rule quality. Use types like api, database, queue, auth, gateway.",
                "items": unspecified,
            })

        missing_proto = []
        insecure_sensitive = []
        unknown_endpoints = []
        cross_zone = []

        for f in (architecture.data_flows or []):
            flow_id = f"{f.source} → {f.destination}"
            if f.source not in component_names or f.destination not in component_names:
                unknown_endpoints.append(flow_id)

            proto = (f.protocol or "").lower().strip()
            if not proto:
                missing_proto.append(flow_id)
            elif f.sensitive and proto in insecure_protocols:
                insecure_sensitive.append(f"{flow_id} ({proto})")

            sz = trust_lookup.get(f.source)
            dz = trust_lookup.get(f.destination)
            if sz and dz and sz != dz:
                cross_zone.append(f"{flow_id} ({sz} → {dz})")

        if unknown_endpoints:
            findings.append({
                "severity": "High",
                "title": "Flows referencing unknown components",
                "details": "Flows should connect defined components. Unknown endpoints often mean missing diagram elements.",
                "items": unknown_endpoints,
            })

        if missing_proto:
            findings.append({
                "severity": "Medium",
                "title": "Flows missing protocol",
                "details": "Specify protocol for each flow (e.g., HTTPS, gRPC, AMQP) to reason about transport protections.",
                "items": missing_proto,
            })

        if insecure_sensitive:
            findings.append({
                "severity": "High",
                "title": "Sensitive data over cleartext/weak protocol",
                "details": "Sensitive flows should use TLS-protected transport (HTTPS/WSS/TLS).",
                "items": insecure_sensitive,
            })

        if cross_zone:
            findings.append({
                "severity": "Info",
                "title": "Cross-trust-boundary flows",
                "details": "Ensure explicit authz/authn, mTLS, and network policies for cross-zone traffic.",
                "items": cross_zone,
            })

        def severity_badge(sev: str) -> str:
            if sev == "High":
                return "bg-red-600"
            if sev == "Medium":
                return "bg-orange-600"
            if sev == "Low":
                return "bg-yellow-600"
            return "bg-blue-600"

        # Pre-render findings HTML (avoid nested f-strings inside f-strings)
        if not findings:
            no_findings_html = '<div class="text-sm text-gray-600">No obvious architecture flaws detected by heuristics.</div>'
        else:
            no_findings_html = ""

        findings_cards_parts = []
        for finding in findings:
            items_parts = []
            for item in (finding.get("items") or []):
                items_parts.append(f"<div class='font-mono'>{item}</div>")
            items_html = "".join(items_parts)

            sev = finding.get("severity", "Info")
            findings_cards_parts.append(
                "".join(
                    [
                        "<div class='border rounded-lg p-4 bg-gray-50'>",
                        "<div class='flex items-center gap-2 mb-2'>",
                        f"<span class='{severity_badge(sev)} text-white px-3 py-1 rounded-full text-xs font-bold uppercase'>{sev}</span>",
                        f"<div class='font-semibold text-gray-800'>{finding.get('title', '')}</div>",
                        "</div>",
                        f"<div class='text-sm text-gray-700 mb-2'>{finding.get('details', '')}</div>",
                        f"<div class='text-xs text-gray-600'>{items_html}</div>",
                        "</div>",
                    ]
                )
            )
        findings_cards_html = "".join(findings_cards_parts)

        # Header with executive summary
        html = f"""
        <div class="bg-gradient-to-r from-indigo-50 to-blue-50 -m-6 p-6 mb-6 rounded-t-lg">
            <h2 class="text-3xl font-bold text-gray-900 mb-2">
                🛡️ Threat Model Report
            </h2>
            <p class="text-lg text-gray-700 mb-4">
                <strong>{architecture.title or 'Untitled Architecture'}</strong>
            </p>
            <div class="flex flex-wrap gap-3 text-sm">
                <span class="bg-white px-3 py-1 rounded-full shadow-sm">
                    <strong>Engine:</strong> {engine_name.upper()}
                </span>
                <span class="bg-white px-3 py-1 rounded-full shadow-sm">
                    <strong>Components:</strong> {len(components)}
                </span>
                <span class="bg-white px-3 py-1 rounded-full shadow-sm">
                    <strong>Total Threats:</strong> {total_threats}
                </span>
            </div>
        </div>
        
        <!-- Executive Summary -->
        <div class="bg-white border-2 border-gray-200 rounded-lg p-6 mb-8 shadow-sm">
            <h3 class="text-xl font-bold text-gray-800 mb-4 flex items-center">
                📊 Executive Summary
            </h3>
            
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                <div class="bg-red-50 border-l-4 border-red-500 p-4 rounded">
                    <div class="text-3xl font-bold text-red-700">{high_risk}</div>
                    <div class="text-sm text-red-600 font-semibold uppercase">High Risk</div>
                    <div class="text-xs text-gray-600 mt-1">Score ≥ 7.5</div>
                </div>
                <div class="bg-orange-50 border-l-4 border-orange-500 p-4 rounded">
                    <div class="text-3xl font-bold text-orange-700">{medium_risk}</div>
                    <div class="text-sm text-orange-600 font-semibold uppercase">Medium Risk</div>
                    <div class="text-xs text-gray-600 mt-1">Score 5.0 - 7.4</div>
                </div>
                <div class="bg-yellow-50 border-l-4 border-yellow-500 p-4 rounded">
                    <div class="text-3xl font-bold text-yellow-700">{low_risk}</div>
                    <div class="text-sm text-yellow-600 font-semibold uppercase">Low Risk</div>
                    <div class="text-xs text-gray-600 mt-1">Score < 5.0</div>
                </div>
            </div>
            
            <div class="border-t pt-4">
                <h4 class="font-semibold text-gray-700 mb-3">Threat Distribution by STRIDE Category</h4>
                <div class="grid grid-cols-2 md:grid-cols-3 gap-3">
                    {' '.join([f'''
                    <div class="flex items-center justify-between bg-gray-50 px-3 py-2 rounded">
                        <span class="text-sm font-medium text-gray-700">{cat}</span>
                        <span class="bg-indigo-600 text-white px-2 py-1 rounded-full text-xs font-bold">{count}</span>
                    </div>
                    ''' for cat, count in stride_counts.items()])}
                </div>
            </div>
        </div>

        <!-- Architecture Overview -->
        <div class="bg-white border-2 border-gray-200 rounded-lg p-6 mb-8 shadow-sm">
            <h3 class="text-xl font-bold text-gray-800 mb-4 flex items-center">
                🧩 Architecture Overview
            </h3>

            <div class="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm mb-6">
                <div class="bg-gray-50 border rounded p-3">
                    <div class="text-2xl font-bold text-gray-800">{len(architecture.components or [])}</div>
                    <div class="text-xs text-gray-600 font-semibold uppercase">Components</div>
                </div>
                <div class="bg-gray-50 border rounded p-3">
                    <div class="text-2xl font-bold text-gray-800">{len(architecture.data_flows or [])}</div>
                    <div class="text-xs text-gray-600 font-semibold uppercase">Data Flows</div>
                </div>
                <div class="bg-gray-50 border rounded p-3">
                    <div class="text-2xl font-bold text-gray-800">{len(architecture.trust_boundaries or [])}</div>
                    <div class="text-xs text-gray-600 font-semibold uppercase">Trust Boundaries</div>
                </div>
            </div>

            <div class="mb-6">
                <h4 class="font-semibold text-gray-700 mb-2">Components</h4>
                <div class="overflow-x-auto">
                    <table class="min-w-full text-sm border">
                        <thead class="bg-gray-100">
                            <tr>
                                <th class="text-left p-2 border">Name</th>
                                <th class="text-left p-2 border">Type</th>
                                <th class="text-left p-2 border">Trust Zone</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join([
                                f"<tr class='border-t'>"
                                f"<td class='p-2 border font-mono text-xs'>{c.name}</td>"
                                f"<td class='p-2 border'>{c.type or ''}</td>"
                                f"<td class='p-2 border'>{trust_lookup.get(c.name, '')}</td>"
                                f"</tr>"
                                for c in (architecture.components or [])
                            ])}
                        </tbody>
                    </table>
                </div>
            </div>

            <div>
                <h4 class="font-semibold text-gray-700 mb-2">Data Flows</h4>
                <div class="overflow-x-auto">
                    <table class="min-w-full text-sm border">
                        <thead class="bg-gray-100">
                            <tr>
                                <th class="text-left p-2 border">Source</th>
                                <th class="text-left p-2 border">Destination</th>
                                <th class="text-left p-2 border">Protocol</th>
                                <th class="text-left p-2 border">Sensitive</th>
                                <th class="text-left p-2 border">Cross-Zone</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join([
                                (lambda f: (
                                    f"<tr class='border-t'>"
                                    f"<td class='p-2 border font-mono text-xs'>{f.source}</td>"
                                    f"<td class='p-2 border font-mono text-xs'>{f.destination}</td>"
                                    f"<td class='p-2 border'>{f.protocol or ''}</td>"
                                    f"<td class='p-2 border'>{'Yes' if f.sensitive else 'No'}</td>"
                                    f"<td class='p-2 border'>{('Yes' if (trust_lookup.get(f.source) and trust_lookup.get(f.destination) and trust_lookup.get(f.source)!=trust_lookup.get(f.destination)) else 'No')}</td>"
                                    f"</tr>"
                                ))(f)
                                for f in (architecture.data_flows or [])
                            ])}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Architecture Flaws -->
        <div class="bg-white border-2 border-gray-200 rounded-lg p-6 mb-8 shadow-sm">
            <h3 class="text-xl font-bold text-gray-800 mb-4 flex items-center">
                🧯 Architecture Flaws / Findings
            </h3>
            {no_findings_html}
            <div class="space-y-4">
                {findings_cards_html}
            </div>
        </div>
        
        <!-- Detailed Threat List -->
        <div class="mb-6">
            <h3 class="text-2xl font-bold text-gray-800 mb-4 flex items-center">
                🔍 Detailed Threat Analysis
            </h3>
        </div>
        
        <div class="space-y-6">
        """
        
        # Sort threats by risk score (highest first)
        sorted_threats = sorted(threat_list, key=lambda t: t.dread.average(), reverse=True)
        
        for i, threat in enumerate(sorted_threats):
            risk = threat.dread.average()
            risk_level = threat.risk_level()
            
            # Determine colors based on risk
            if risk >= 7.5:
                border_color = "border-red-300"
                bg_color = "bg-red-50"
                badge_color = "bg-red-600"
                severity_text = "text-red-800"
            elif risk >= 5.0:
                border_color = "border-orange-300"
                bg_color = "bg-orange-50"
                badge_color = "bg-orange-600"
                severity_text = "text-orange-800"
            else:
                border_color = "border-yellow-300"
                bg_color = "bg-yellow-50"
                badge_color = "bg-yellow-600"
                severity_text = "text-yellow-800"
            
            # Get DREAD scores
            dread = threat.dread
            
            html += f"""
            <div class="border-2 {border_color} rounded-xl overflow-hidden shadow-md hover:shadow-xl transition-all">
                <!-- Header -->
                <div class="{bg_color} border-b-2 {border_color} p-5">
                    <div class="flex justify-between items-start gap-4 mb-3">
                        <div class="flex-1">
                            <div class="flex items-center gap-2 mb-2">
                                <span class="text-xs font-bold text-gray-500">THREAT #{i + 1}</span>
                                <span class="{badge_color} text-white px-3 py-1 rounded-full text-xs font-bold uppercase">
                                    {risk_level} Risk
                                </span>
                                <span class="bg-indigo-600 text-white px-3 py-1 rounded-full text-xs font-bold uppercase">
                                    {threat.stride_category.value}
                                </span>
                            </div>
                            <h4 class="text-xl font-bold {severity_text} leading-tight">
                                {threat.threat}
                            </h4>
                        </div>
                        <div class="text-right">
                            <div class="text-4xl font-black {severity_text}">{risk:.1f}</div>
                            <div class="text-xs text-gray-600 font-semibold">/ 10</div>
                        </div>
                    </div>
                    
                    <div class="flex flex-wrap gap-2 text-sm">
                        <span class="bg-white bg-opacity-70 px-3 py-1 rounded-full text-gray-700">
                            <strong>Component:</strong> {threat.component}
                        </span>
                        <span class="bg-white bg-opacity-70 px-3 py-1 rounded-full text-gray-700">
                            <strong>Methodology:</strong> {threat.methodology}
                        </span>
                    </div>
                </div>
                
                <!-- Body -->
                <div class="bg-white p-5">
                    <!-- DREAD Breakdown -->
                    <div class="mb-5">
                        <h5 class="font-bold text-gray-800 mb-3 text-sm uppercase tracking-wide flex items-center">
                            📈 DREAD Score Breakdown
                        </h5>
                        <div class="grid grid-cols-2 md:grid-cols-5 gap-3">
                            <div class="text-center p-3 bg-gray-50 rounded-lg border">
                                <div class="text-2xl font-bold text-indigo-600">{dread.damage}</div>
                                <div class="text-xs text-gray-600 font-semibold mt-1">Damage</div>
                            </div>
                            <div class="text-center p-3 bg-gray-50 rounded-lg border">
                                <div class="text-2xl font-bold text-indigo-600">{dread.reproducibility}</div>
                                <div class="text-xs text-gray-600 font-semibold mt-1">Reproducibility</div>
                            </div>
                            <div class="text-center p-3 bg-gray-50 rounded-lg border">
                                <div class="text-2xl font-bold text-indigo-600">{dread.exploitability}</div>
                                <div class="text-xs text-gray-600 font-semibold mt-1">Exploitability</div>
                            </div>
                            <div class="text-center p-3 bg-gray-50 rounded-lg border">
                                <div class="text-2xl font-bold text-indigo-600">{dread.affected_users}</div>
                                <div class="text-xs text-gray-600 font-semibold mt-1">Affected Users</div>
                            </div>
                            <div class="text-center p-3 bg-gray-50 rounded-lg border">
                                <div class="text-2xl font-bold text-indigo-600">{dread.discoverability}</div>
                                <div class="text-xs text-gray-600 font-semibold mt-1">Discoverability</div>
                            </div>
                        </div>
                        <div class="mt-2 text-xs text-gray-500 text-center">
                            Total DREAD Score: {dread.total()}/50 | Average: {risk:.2f}/10
                        </div>
                    </div>
                    
                    <!-- Mitigation -->
                    <div class="mb-4 bg-green-50 border-l-4 border-green-500 p-4 rounded">
                        <h5 class="font-bold text-green-800 mb-2 text-sm uppercase tracking-wide flex items-center">
                            ✅ Recommended Mitigation
                        </h5>
                        <p class="text-gray-700 leading-relaxed">{threat.mitigation}</p>
                    </div>
                    
                    <!-- References -->
                    {f'''
                    <div class="bg-blue-50 border-l-4 border-blue-500 p-4 rounded">
                        <h5 class="font-bold text-blue-800 mb-2 text-sm uppercase tracking-wide">
                            📚 References
                        </h5>
                        <div class="flex flex-wrap gap-2">
                            {' '.join([f'<span class="bg-white px-2 py-1 rounded text-xs text-gray-700 border border-blue-200">{ref}</span>' for ref in threat.references])}
                        </div>
                    </div>
                    ''' if threat.references else ''}
                </div>
            </div>
            """
        
        html += """
        </div>
        
        <!-- Footer -->
        <div class="mt-8 pt-6 border-t-2 border-gray-200 text-center text-sm text-gray-500">
            <p>Generated by Shell Threat Model | Report generated on """ + __import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
        </div>
        """
        
        return html

    # Bind event
    analyze_proxy = create_proxy(run_analysis)
    document.getElementById("analyze-btn").addEventListener("click", analyze_proxy)

    download_html_proxy = create_proxy(download_html)
    download_md_proxy = create_proxy(download_md)
    download_json_proxy = create_proxy(download_json)
    document.getElementById("download-html-btn").addEventListener("click", download_html_proxy)
    document.getElementById("download-md-btn").addEventListener("click", download_md_proxy)
    document.getElementById("download-json-btn").addEventListener("click", download_json_proxy)

asyncio.ensure_future(setup())
