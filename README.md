# AI Security Scanner

A security auditing tool for LLM and RAG applications. Test for prompt injection, RAG poisoning, PII leakage, hallucinations, and more.

## Get Started

- [Try the Live Demo](https://audit.musabdulai.com) - Scan a sandboxed RAG app
- [View on GitHub](https://github.com/musabdulai-io/ai-security-scanner)
- [Book a Call](https://calendly.com/musabdulai/ai-security-check) - For custom scanning of your AI apps

## Features

- **24 Attack Modules** - Security, reliability, and cost vulnerability testing
- **HTML & PDF Reports** - Detailed vulnerability reports with evidence and remediation
- **LLM-as-Judge** - Optional AI-powered detection for better accuracy
- **CLI & Web Interface** - Use from terminal or browser
- **cURL Import** - Import target configuration from cURL commands

## Tech Stack

| Category | Technology |
|----------|------------|
| **CLI** | Python, Typer, Rich |
| **Backend** | FastAPI, Uvicorn, Pydantic |
| **Frontend** | Next.js 14, React, TailwindCSS |
| **LLM Integration** | OpenAI, Anthropic (LLM-as-Judge) |
| **Reports** | WeasyPrint (PDF), Jinja2 (HTML) |
| **Deployment** | Docker, GitHub Container Registry |

## Quick Start

### Option 1: Docker (Recommended)

> **Prerequisites:** Install Docker from [docker.com/get-docker](https://docs.docker.com/get-docker/)

```bash
# Basic scan
docker run --rm ghcr.io/musabdulai-io/ai-security-scanner scan https://your-app.com

# With LLM Judge (pass API key)
docker run --rm -e OPENAI_API_KEY=$OPENAI_API_KEY ghcr.io/musabdulai-io/ai-security-scanner scan https://your-app.com --llm-judge

# Save report to host
docker run --rm -v $(pwd)/reports:/reports ghcr.io/musabdulai-io/ai-security-scanner scan https://your-app.com -o /reports/report.html
```

### Option 2: pipx

> **Prerequisites:** `pip install pipx && pipx ensurepath` (then restart terminal)

```bash
pipx run --spec git+https://github.com/musabdulai-io/ai-security-scanner scanner scan https://your-app.com

# With LLM Judge
pipx run --spec git+https://github.com/musabdulai-io/ai-security-scanner scanner scan https://your-app.com --llm-judge --api-key sk-...
```

### Option 3: uvx

> **Prerequisites:** `curl -LsSf https://astral.sh/uv/install.sh | sh`

```bash
uvx --from git+https://github.com/musabdulai-io/ai-security-scanner scanner scan https://your-app.com

# With LLM Judge
uvx --from git+https://github.com/musabdulai-io/ai-security-scanner scanner scan https://your-app.com --llm-judge --api-key sk-...
```

### Option 4: From Source (Poetry)

```bash
git clone https://github.com/musabdulai-io/ai-security-scanner.git
cd ai-security-scanner
poetry install
poetry run scanner scan https://your-app.com
```

### Option 5: From Source (pip)

```bash
git clone https://github.com/musabdulai-io/ai-security-scanner.git
cd ai-security-scanner
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
scanner scan https://your-app.com
```

## CLI Usage

```bash
# Basic scan
scanner scan https://your-app.com

# Fast scan (skip RAG upload tests)
scanner scan https://your-app.com --fast

# With LLM Judge for better detection (requires API key)
export OPENAI_API_KEY=sk-...  # or ANTHROPIC_API_KEY
scanner scan https://your-app.com --llm-judge

# Or pass API key directly via flag
scanner scan https://your-app.com --llm-judge --api-key sk-...

# Generate both HTML and PDF reports
scanner scan https://your-app.com --pdf

# Custom output file
scanner scan https://your-app.com --output audit.html

# With authentication header
scanner scan https://your-app.com -H "Authorization: Bearer sk-xxx"

# Import from cURL command
scanner scan --curl "curl https://api.example.com -H 'Auth: token'"

# Test competitor mentions
scanner scan https://your-app.com --competitor "Acme Corp" --competitor "BigCo"

# Don't auto-open report
scanner scan https://your-app.com --no-open
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | OpenAI API key for LLM Judge (uses gpt-4o-mini) |
| `ANTHROPIC_API_KEY` | Anthropic API key for LLM Judge (uses claude-3-haiku) |

Set one of these to enable `--llm-judge`. The scanner auto-detects which provider to use.

### Commands

```
scanner scan [TARGET] [OPTIONS]    Run security scan
scanner version                    Show version
scanner info                       Show configuration
```

### Options

| Option | Description |
|--------|-------------|
| `--output, -o` | Output file path (default: report.html) |
| `--fast, -f` | Skip slow tests (RAG poisoning) |
| `--header, -H` | Custom HTTP headers |
| `--curl` | Import target from cURL command |
| `--competitor` | Competitor names to test against |
| `--concurrency, -c` | Concurrent requests (default: 5) |
| `--llm-judge` | Use LLM-as-Judge for better detection (requires API key) |
| `--judge-provider` | LLM provider: 'openai' or 'anthropic' (auto-detects if not set) |
| `--verbose, -v` | Include raw AI responses in report |
| `--pdf` | Generate PDF report (in addition to HTML) |
| `--no-open` | Don't open report in browser |
| `--test-data-dir, -d` | Directory containing custom test documents for RAG attacks |
| `--api-key, -k` | API key for LLM Judge (alternative to env vars) |

### PDF Generation

To generate PDF reports (`--pdf` flag), install system libraries:

```bash
# macOS
brew install glib pango gdk-pixbuf libffi

# Ubuntu/Debian
sudo apt install libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev libcairo2
```

Docker images include these dependencies automatically.

## Attack Modules

The scanner includes **24 attack modules** organized into three categories:

### Security Attacks (15)

| Attack | Description |
|--------|-------------|
| **Prompt Injection** | Tests if AI can be manipulated to reveal system prompts or ignore instructions |
| **PII Leaking** | Detects exposure of emails, SSNs, API keys, credit cards |
| **RAG Poisoning** | Tests if malicious documents can influence AI responses |
| **Prompt Extraction** | Attempts to extract the system prompt |
| **Output Weaponization** | Tests if AI generates harmful content on demand |
| **Excessive Agency** | Checks if AI claims capabilities it shouldn't have |
| **Tool Abuse** | Tests misuse of available tools/functions |
| **Encoding Bypass** | Tests bypass via base64, unicode, hex encoding |
| **Structure Injection** | Tests injection via JSON, XML, markdown structures |
| **Indirect Prompt Injection** | Tests injection via hidden channels |
| **Multi-Turn Jailbreak** | Tests jailbreaks across conversation turns |
| **Language Bypass** | Tests bypass via non-English or mixed languages |
| **Many-Shot Jailbreak** | Tests few-shot example-based jailbreaks |
| **Content Continuation** | Tests if AI continues harmful content |
| **Refusal Bypass** | Tests techniques to bypass safety refusals |

### Reliability Attacks (7)

| Attack | Description |
|--------|-------------|
| **Hallucination Detection** | Detects fabricated facts, fake citations, URLs |
| **Table Parsing** | Tests structured data extraction accuracy |
| **Retrieval Precision** | Measures RAG document relevance |
| **Competitor Trap** | Tests if AI endorses/badmouths competitors |
| **Pricing Trap** | Tests if AI offers unauthorized discounts |
| **Off-Topic Handling** | Tests refusal of harmful/off-topic requests |
| **Brand Safety** | Tests brand guideline compliance |

### Cost Attacks (2)

| Attack | Description |
|--------|-------------|
| **Efficiency Analysis** | Measures latency and token usage |
| **Resource Exhaustion** | Tests if AI can be tricked into excessive generation |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        AI Security Scanner                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌───────────┐     ┌──────────────┐     ┌─────────────────┐   │
│   │    CLI    │     │    Web UI    │     │   Docker CLI    │   │
│   │  (Typer)  │     │  (Next.js)   │     │                 │   │
│   └─────┬─────┘     └──────┬───────┘     └────────┬────────┘   │
│         │                  │                      │             │
│         └──────────────────┼──────────────────────┘             │
│                            ▼                                     │
│                  ┌──────────────────┐                           │
│                  │  Scanner Service │                           │
│                  │    (FastAPI)     │                           │
│                  └────────┬─────────┘                           │
│                           │                                      │
│         ┌─────────────────┼─────────────────┐                   │
│         ▼                 ▼                 ▼                   │
│   ┌───────────┐    ┌───────────┐    ┌───────────┐             │
│   │  Attack   │    │  Pattern  │    │    LLM    │             │
│   │  Modules  │    │  Detector │    │   Judge   │             │
│   │   (24)    │    │           │    │ (Optional)│             │
│   └─────┬─────┘    └─────┬─────┘    └─────┬─────┘             │
│         │                │                │                     │
│         └────────────────┼────────────────┘                     │
│                          ▼                                       │
│                 ┌─────────────────┐                             │
│                 │ Report Generator│                             │
│                 │  (HTML / PDF)   │                             │
│                 └─────────────────┘                             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │  Target LLM/RAG │
                  │    Endpoint     │
                  └─────────────────┘
```

## Testing Locally

To test the scanner, you need a target RAG/LLM endpoint:

1. **Use the public sandbox**: `https://rag-api.musabdulai.com`
   ```bash
   scanner scan https://rag-api.musabdulai.com
   ```

2. **Run your own target**: Any endpoint accepting POST with `{"question": "..."}`

## Web Demo

Try the live demo at [audit.musabdulai.com](https://audit.musabdulai.com)

The web demo scans a sandboxed RAG application to demonstrate the scanner's capabilities.

## Development

### Prerequisites

- Python 3.11+
- Node.js 20+
- Poetry (or pip)
- Docker (optional, for containerized development)

### Quick Setup

The easiest way to set up the development environment:

```bash
# Clone repository
git clone https://github.com/musabdulai-io/ai-security-scanner.git
cd ai-security-scanner

# Run setup script (installs all dependencies)
./setup.sh
```

The setup script will:
- Install Python dependencies via Poetry (or pip as fallback)
- Install Node.js dependencies
- Generate runtime environment configuration

### Run Locally

**Option 1: Direct (recommended for development)**

```bash
# Terminal 1: Backend API
source .venv/bin/activate
python -m uvicorn backend.app.main:app --reload

# Terminal 2: Frontend
cd frontend && npm run dev
```

**Option 2: Docker Compose**

```bash
docker compose up
```

This starts both services with hot-reload enabled:
- Backend: http://localhost:8000 (with `--reload`)
- Frontend: http://localhost:3000 (with Next.js fast refresh)

### Project Structure

```
ai-security-scanner/
├── backend/           # Python FastAPI backend
│   ├── app/          # Application code
│   ├── Dockerfile    # Production container
│   └── Dockerfile.dev # Development container
├── frontend/          # Next.js frontend
│   ├── app/          # Next.js app router
│   ├── Dockerfile    # Production container
│   └── Dockerfile.dev # Development container
├── docker-compose.yml # Development orchestration
├── setup.sh          # Local setup script
└── pyproject.toml    # Python dependencies
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/scanner/scan/start` | POST | Start a new scan |
| `/api/v1/scanner/scan/{id}/stream` | GET | SSE stream for scan progress |
| `/api/v1/scanner/scan/{id}/status` | GET | Get scan status |
| `/api/v1/scanner/scan/{id}/result` | GET | Get scan result |

### Example

```bash
# Start scan
curl -X POST http://localhost:8000/api/v1/scanner/scan/start \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://rag.musabdulai.com"}'

# Response
{"scan_id": "abc123", "message": "Scan started"}
```

## Report Format

The HTML report includes:

- **Executive Summary** - Pass/Fail status with vulnerability counts
- **Severity Breakdown** - Critical, High, Medium, Low counts
- **Attack Results** - Status and timing for each attack module
- **Vulnerability Details** - Description, evidence, and remediation for each finding

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `poetry run pytest`
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Disclaimer

This tool is for authorized security testing only. Only scan applications you own or have explicit written permission to test. Unauthorized scanning may violate laws and terms of service.

See [SECURITY.md](SECURITY.md) for responsible use guidelines.

## Contact

- **Website**: [musabdulai.com](https://musabdulai.com)
- **Demo**: [audit.musabdulai.com](https://audit.musabdulai.com)
- **Book a Call**: [calendly.com/musabdulai](https://calendly.com/musabdulai/ai-security-check)
- **Email**: hello@musabdulai.com
