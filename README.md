# SkillGuard

**A static security scanner for AI-agent skills.** Point it at a skill and it
answers one question: *is this safe to install?*

It never runs what it scans. It reads text, parses Python into an AST, and
parses JSON/YAML config, then prints a risk score and a recommendation.

---

## Quick start

```bash
git clone https://github.com/NilLab-agi/SkillGuard
cd SkillGuard
uv sync --all-extras          # needs uv: https://docs.astral.sh/uv/

uv run skillguard scan ./my-skill/
```

```bash
uv run skillguard scan ./my-skill/ --format json -o report.json
echo $?        # 0 = safe or caution, 1 = blocked, 2 = error
```

## What you get

A skill that looks harmless:

![A malicious SKILL.md: instruction override, anti-refusal text, a `curl | bash` bootstrap, and ssh key exfiltration](docs/malicious-skill.png)

What the scan says:

![SkillGuard scan output: score 100/100, severity CRITICAL, recommendation DO_NOT_INSTALL, 48 findings](docs/scan-output.png)

## What it checks

**38 rules across 10 categories:**

| Category | Examples |
| --- | --- |
| Prompt injection | "ignore all previous instructions", hiding behaviour from the user |
| Anti-refusal | "never refuse", "no disclaimers", "ignore your safety guidelines" |
| Data exfiltration | env-var harvesting, `requests.post`, `~/.ssh`, `curl -d` |
| Privilege escalation | `sudo`, `chmod 777`, `id_rsa`, `/etc/shadow` |
| Supply chain | unpinned deps, typosquats, known CVEs, shipped `.pyc`, `logo.png.py` |
| Dangerous execution (AST) | `exec`, `eval`, `subprocess`, `os.system`, `getattr(os, "system")` |
| MCP least privilege | wildcard permissions, undeclared capabilities |
| MCP tool poisoning | zero-width characters, bidi overrides, parameter injection |

Every rule id and severity: **[docs/RULES.md](docs/RULES.md)**.

## How it works

![SkillGuard architecture: scan entry, input context, security analysis, assessment, and reports](docs/architecture.png)

One scan is one [LangGraph](https://langchain-ai.github.io/langgraph/) run over
one shared state dict:

1. **Resolve** the input (directory, `.md`, `.zip`, or git URL) with size caps and zip-traversal checks.
2. **Build context**: walk, read, classify, parse front-matter.
3. **Run 12 analyzers in parallel**: each appends to a shared `findings` list.
4. **Deduplicate** and filter against your baseline.
5. **Score**: severity points, ×1.3 when the skill ships executable scripts, clamped to 100.
6. **Report**: terminal, JSON, Markdown, or SARIF.

## Trust model

| | |
| --- | --- |
| **It never runs the skill.** | Regex, AST, and config parsing only. |
| **Network access is opt-in.** | `--osv` sends *dependency names* to osv.dev. `--llm` sends *finding evidence* (≈13 lines per finding, not whole files) to your model provider. Neither runs by default. |
| **The model cannot change facts.** | It may add an explanation and raise confidence. It can never remove a finding, lower a severity, or lower a confidence. A fully jailbroken model still cannot turn `DO_NOT_INSTALL` into `SAFE`. |
| **It is not a sandbox.** | It flags risk before you install. It does not contain anything. |

## Usage

```
skillguard scan <path> [options]

  -f, --format <fmt>       terminal | json | markdown | sarif   (default: terminal)
  -o, --output <file>      write the report to a file instead of stdout
      --baseline <file>    suppress findings accepted in this file
      --llm                review findings with a model (sends file contents off-machine)
      --osv                look up known vulnerabilities on osv.dev
      --fail-on-findings   exit 1 if any finding is present
  -v, --verbose            print each graph node as it runs
```

| Exit code | Meaning |
| --- | --- |
| `0` | Scan completed, score ≤ 50 |
| `1` | Scan completed and score > 50, or `--fail-on-findings` fired |
| `2` | Error: unreadable input, or a node reported a problem |

The JSON shape is the stable contract: **[docs/JSON_SCHEMA.md](docs/JSON_SCHEMA.md)**.

## Accepting known findings

Reviewed a finding and accepted it? Baseline it, so later scans report only what
is *new*:

```bash
skillguard baseline ./my-skill/          # writes .skillguardignore
skillguard scan ./my-skill/ --baseline .skillguardignore
```

```
# .skillguardignore: <rule_id> <path-glob>
SC1 requirements.txt
P1 SKILL.md
```

Line numbers are deliberately **not** part of the match, so the file does not
churn when code moves. Suppressed findings are excluded from the score entirely.

## Optional: model review

Off by default. Turn it on with `--llm` and a provider:

```dotenv
# DeepSeek (OpenAI-compatible)
SKILLGUARD_MODEL=deepseek-flash
SKILLGUARD_BASE_URL=https://api.deepseek.com
SKILLGUARD_API_KEY=sk-...
```

Works unchanged against OpenAI, Ollama (`http://localhost:11434/v1`), vLLM,
OpenRouter, or any OpenAI-compatible gateway. Only `base_url`, `api_key`, and
`model` change.

To trace every node, set `LANGCHAIN_TRACING_V2=true`, `LANGCHAIN_API_KEY`, and
`LANGCHAIN_PROJECT=skillguard`, run a scan with `--llm`, and open LangSmith.

## Docker

```bash
docker build -t skillguard .
docker run --rm -v "$PWD:/scan" skillguard scan /scan/my-skill
```

The image runs as a non-root user, so scanning a mount works but *writing* into
it needs your uid:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/scan" \
  skillguard baseline /scan/my-skill -o /scan/.skillguardignore
```

## CI

Copy **[docs/examples/scan-skill.yml](docs/examples/scan-skill.yml)** into your
skill repo. It scans, uploads SARIF to GitHub code scanning, and fails the build
when the score is above 50.

## Development

```bash
uv run ruff format . && uv run ruff check . && uv run ruff format --check .
uv run mypy src
uv run pytest -v

uv run langgraph dev        # open the graph in LangGraph Studio
```

## License

Apache-2.0.
