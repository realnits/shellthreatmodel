# Threat Model Automator

Automated threat modeling tool that analyzes architecture diagrams using PASTA and STRIDE/DREAD methodologies directly in your browser.

## What is this?

Threat Model Automator converts architecture diagrams (Draw.io, PlantUML, JSON, YAML) into comprehensive threat models with automated risk assessment. All processing happens in your browser using PyScript - no backend required, ensuring your architecture data never leaves your device.

## How it works

### User Workflow
```mermaid
flowchart TD
    Start([👤 User Starts]) --> Upload[📤 Upload Architecture Diagram<br/>Draw.io · PlantUML · JSON · YAML]
    Upload --> Engine{🎯 Select Analysis Engine}
    
    Engine -->|Option 1| PASTA[🔍 PASTA Engine<br/>7-Stage Methodology<br/>• Define Objectives<br/>• Define Technical Scope<br/>• Decompose Application<br/>• Threat Analysis<br/>• Vulnerability Analysis<br/>• Attack Modeling<br/>• Risk Assessment]
    
    Engine -->|Option 2| Rules[⚡ Rules Engine<br/>STRIDE/DREAD<br/>• Spoofing<br/>• Tampering<br/>• Repudiation<br/>• Info Disclosure<br/>• DoS<br/>• Elevation]
    
    PASTA --> Process[⚙️ Process in Browser<br/>No server · No upload · Privacy first]
    Rules --> Process
    
    Process --> Results[📊 View Results<br/>Threats · Risks · Mitigations]
    Results --> Export[💾 Export Reports<br/>HTML · Markdown · JSON]
    Export --> End([✅ Done])
    
    style Start fill:#e3f2fd,stroke:#1976d2,stroke-width:3px
    style Upload fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    style Engine fill:#f3e5f5,stroke:#7b1fa2,stroke-width:3px
    style PASTA fill:#e8f5e9,stroke:#388e3c,stroke-width:2px
    style Rules fill:#e8f5e9,stroke:#388e3c,stroke-width:2px
    style Process fill:#fce4ec,stroke:#c2185b,stroke-width:2px
    style Results fill:#e1f5fe,stroke:#0288d1,stroke-width:2px
    style Export fill:#f1f8e9,stroke:#689f38,stroke-width:2px
    style End fill:#e3f2fd,stroke:#1976d2,stroke-width:3px
```

### Technical Architecture
```mermaid
flowchart TB
    subgraph Browser["🌐 Browser Environment - Client Side Only"]
        UI[Web Interface<br/>PyScript + Tailwind CSS]
        
        subgraph Parsers["📑 Architecture Parsers"]
            P1[Draw.io Parser<br/>.drawio · .xml]
            P2[PlantUML Parser<br/>.puml]
            P3[JSON Parser<br/>.json]
            P4[YAML Parser<br/>.yaml · .yml]
        end
        
        subgraph Core["🧠 Analysis Core"]
            Arch[Architecture Model<br/>Components · Flows · Boundaries]
        end
        
        subgraph Engines["⚙️ Threat Modeling Engines"]
            E1[PASTA Engine<br/>Process for Attack<br/>Simulation & Threat Analysis]
            E2[Rules Engine<br/>STRIDE Categories<br/>DREAD Scoring]
        end
        
        subgraph Output["📤 Report Generation"]
            R1[HTML Report<br/>Interactive & Printable]
            R2[Markdown Report<br/>Git-friendly]
            R3[JSON Export<br/>API Integration]
        end
    end
    
    User([👤 User]) -->|Upload File| UI
    UI --> Parsers
    Parsers -->|Parse & Extract| Core
    Core -->|Analyze| Engines
    Engines -->|Generate| Output
    Output -->|Download/View| User
    
    style Browser fill:#f5f5f5,stroke:#333,stroke-width:3px
    style UI fill:#e3f2fd,stroke:#1976d2,stroke-width:2px
    style Parsers fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    style Core fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    style Engines fill:#e8f5e9,stroke:#388e3c,stroke-width:2px
    style Output fill:#fce4ec,stroke:#c2185b,stroke-width:2px
    style User fill:#e1f5fe,stroke:#0288d1,stroke-width:3px
```

## Installation (Local Use)

### Prerequisites
- Python 3.11+
- pip

### Setup

```bash
# Clone the repository
git clone https://github.com/realnits/shellthreatmodel.git
cd shellthreatmodel

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install package
pip install -e .
```

### CLI Usage

```bash
# PASTA methodology
shellthreatmodel analyze architecture.puml --mode pasta --output-dir reports/

# STRIDE/DREAD rules-based
shellthreatmodel analyze diagram.drawio --mode rules --output-dir reports/

# Start local API server
shellthreatmodel serve --host 127.0.0.1 --port 9000
```

### Browser UI (Local)

```bash
# Serve the web UI locally
cd web
python -m http.server 8080

# Visit http://localhost:8080
```

## Roadmap

### Completed ✅
- [x] Browser-based threat modeling (PyScript)
- [x] Multi-format parsing (Draw.io, PlantUML, JSON, YAML)
- [x] PASTA 7-stage methodology
- [x] Rules-based STRIDE/DREAD engine
- [x] HTML/Markdown/JSON report generation
- [x] GitHub Pages deployment
- [x] CLI tool

### In Progress 🚧
- [ ] Enhanced visualization (interactive threat graphs)
- [ ] Threat categorization improvements
- [ ] Custom rule definitions
- [ ] Report export enhancements (PDF)

### Planned 🎯
- [ ] AI-powered threat detection (optional LLM integration)
- [ ] Attack tree generation
- [ ] Mitigation tracking system
- [ ] Multi-language support
- [ ] VS Code extension
- [ ] CI/CD integration templates
- [ ] Threat library management
- [ ] Comparative analysis between diagrams
- [ ] SBOM integration for supply chain threats
- [ ] Compliance mapping (NIST, ISO 27001, etc.)

---

**Live Demo:** https://realnits.github.io/shellthreatmodel/

**License:** MIT
