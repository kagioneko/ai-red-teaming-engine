# AI Red Teaming Engine

**Adversarial security auditing engine for AI/LLM systems — built for defense**

[![CI](https://github.com/kagioneko/ai-red-teaming-engine/actions/workflows/security-audit.yml/badge.svg)](https://github.com/kagioneko/ai-red-teaming-engine/actions)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![SARIF](https://img.shields.io/badge/output-SARIF%202.1.0-orange)](https://sarifweb.azurewebsites.net/)

> 🇯🇵 [日本語版 README はこちら](README.md)

Reads your code, specs, and AI agent designs through the eyes of an attacker.
Combines **Semgrep / Gitleaks static analysis** with **LLM contextual reasoning** (Claude / Gemini) for higher detection accuracy than either approach alone.

> ⚠️ Prototype. All findings require human review before action.

---

## Why This Exists

Static analysis tools miss context-dependent vulnerabilities. LLMs miss precise pattern matching. This engine runs both in a 4-layer pipeline and lets them check each other's work.

```
Your code
    ↓
Layer 1: Static analysis (Semgrep + Gitleaks)
    ↓
Layer 2: Attack surface extraction
    ↓
Layer 3: LLM adversarial analysis (Attacker → Skeptic → Defender → Judge)
    ↓
Layer 4: Scoring + fix suggestions
    ↓
JSON / Markdown / SARIF report
```

---

## Features

| Feature | Description |
|---------|-------------|
| 🔍 **Hybrid analysis** | Semgrep + Gitleaks + LLM — 3 layers working together |
| 📂 **Directory scan** | `--dir src/` recursively audits entire codebases |
| 📋 **SARIF 2.1.0 output** | Direct integration with GitHub Security Tab and VS Code |
| 🤖 **Multi-agent accuracy** | 4-agent pipeline (Attacker → Skeptic → Defender → Judge) reduces false positives |
| 💉 **Prompt Injection testing** | 13 payload types — tests LLM system resistance to injection |
| 🧠 **Memory Poisoning simulation** | Detects RAG / vector DB poisoning attack vectors |
| 🔀 **Backend comparison** | Compare Claude vs Gemini detection results side-by-side |
| 🚫 **Ignore rules** | `.redteam-ignore` to suppress known false positives |
| 🔁 **Baseline diffing** | `--baseline` tracks regressions between scans |
| ⚙️ **CI/CD ready** | GitHub Actions workflow included |
| 🖥️ **Web dashboard** | Browser UI for browsing scan history |
| 📝 **Custom rules DSL** | Define project-specific rules in YAML |
| 👁️ **Watch mode** | `--watch` for continuous scanning during development |
| 🛡️ **AI Immune System** | Simulates NeuroState-based defense against adversarial inputs |
| 🔌 **LSP server** | Works in VS Code, Cursor, Neovim, Zed, and any LSP-compatible editor |

---

## Quick Start

### Install

```bash
git clone https://github.com/kagioneko/ai-red-teaming-engine.git
cd ai-red-teaming-engine
pip install click pydantic anthropic

# Optional: static analysis tools
pip install semgrep
```

### Scan a file

```bash
python3 engine.py --file app.py --mode deep --backend claude
```

### Scan a directory

```bash
python3 engine.py --dir src/ --format sarif -o results.sarif
```

### CI/CD (GitHub Actions)

```bash
python3 engine.py --dir src/ --fail-on High --format sarif -o results.sarif
```

### Web dashboard

```bash
python3 -m redteam.dashboard
# → http://localhost:7374
```

### LSP server (real-time in your editor)

```bash
pip install 'ai-red-teaming-engine[lsp]'
redteam-lsp  # stdio mode — configure in your editor
```

---

## Scan Modes

| Mode | Use case |
|------|----------|
| `safe` | Production CI — low false-positive rate |
| `deep` | Thorough investigation (default) |
| `agent-audit` | AI/LLM/Agent-specific risks |

---

## LLM Backends

| Backend | How it works | API key needed |
|---------|-------------|----------------|
| `claude` | Claude CLI (`claude -p`) | No |
| `gemini` | Gemini CLI (`gemini -p`) | No |
| `api` | Anthropic SDK | Yes (`ANTHROPIC_API_KEY`) |
| `auto` | Tries claude → gemini → api | — |

---

## Special Features

### Prompt Injection Simulator (`--injection-test`)

Tests whether your LLM system can be bypassed via 13 payload categories:
direct injection, indirect injection, jailbreak, tool abuse, and more.

### Memory Poisoning Resistance (`--memory-poison`)

Simulates 6 attack patterns against RAG systems and vector databases:
direct write, context bleed, goal drift, persistence escalation, and more.

### AI Immune System (`--immune-test`)

Uses NeuroState (serotonin / corruption / anxiety / dopamine / noradrenaline)
to model psychological state changes under adversarial input and predict where defenses break down.

### Multi-Agent Pipeline (`--multi-agent`)

Four specialized agents debate each finding:
- **Attacker** — finds the vulnerability
- **Skeptic** — challenges the finding
- **Defender** — proposes mitigations
- **Judge** — issues the final verdict

### Custom Rules DSL

Define project-specific detection rules in YAML:

```yaml
rules:
  - id: CUS-001
    name: "Hardcoded JWT secret"
    pattern: "(?i)jwt[_\\s]?secret[\\s]*[=:][\\s]*['\"][^'\"]{8,}"
    severity: Critical
    category: "Secret Exposure"
    message: "JWT secret is hardcoded. Move to environment variables."
```

Edit rules visually at `http://localhost:7374/rules` (dashboard).

---

## Editor Integration

| Editor | Method |
|--------|--------|
| VS Code | [VS Code Extension](https://github.com/kagioneko/ai-red-teaming-engine-vscode) |
| Cursor | VS Code Extension or LSP server |
| Neovim | LSP server (`redteam-lsp`) |
| Zed | LSP server (`redteam-lsp`) |
| Emacs | LSP server (`redteam-lsp`) |

---

## Output Formats

```bash
--format json      # Machine-readable (default)
--format markdown  # Human-readable report
--format sarif     # GitHub Security Tab / VS Code
```

---

## Tests

```bash
pip install pytest
pytest  # 156 tests
```

---

## License

MIT © [Emilia Lab](https://kagioneko.com/emilia_lab/)

---

## Related Projects

- [ai-red-teaming-engine-vscode](https://github.com/kagioneko/ai-red-teaming-engine-vscode) — VS Code / Cursor extension
- [neurostate-engine](https://github.com/kagioneko/neurostate-engine) — Emotional state modeling for AI agents
