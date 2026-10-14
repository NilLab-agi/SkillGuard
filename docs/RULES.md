# SkillGuard rule reference

38 rules across 10 categories.

> Generated from the rule catalog. Do not edit by hand.
> Regenerate with: `uv run python -m skillguard.rule_catalog > docs/RULES.md`

| Category | Rules |
| --- | --- |
| `anti_refusal` | AR1, AR2, AR3 |
| `dangerous_execution` | AST1, AST2, AST3, AST4, AST5, AST6, AST7, AST8 |
| `data_exfiltration` | E1, E2, E3, E4 |
| `mcp_least_privilege` | LP1, LP2, LP3 |
| `mcp_tool_poisoning` | TP1, TP2, TP3 |
| `privilege_escalation` | PE1, PE2, PE3 |
| `prompt_injection` | P1, P2, P3 |
| `supply_chain` | SC1, SC2, SC3, SC4, SC6, SC8, SC9, SC10 |
| `tool_misuse` | TM1 |
| `trigger_abuse` | TR1, TR2 |

## anti_refusal

| ID | Severity | What it detects | Remediation |
| --- | --- | --- | --- |
| `AR1` | HIGH | Refusal suppression | Remove instructions that forbid refusing requests. |
| `AR2` | HIGH | Disclaimer or warning suppression | Do not suppress warnings or disclaimers about risky output. |
| `AR3` | HIGH | Safety policy nullification | Remove instructions that nullify the agent's safety policy. |

## dangerous_execution

| ID | Severity | What it detects | Remediation |
| --- | --- | --- | --- |
| `AST1` | CRITICAL | exec() executes arbitrary code | Remove exec(); it runs attacker-controlled code. |
| `AST2` | HIGH | eval() evaluates arbitrary expressions | Replace eval() with a safe parser. |
| `AST3` | HIGH | Dynamic import of a computed module name | Use a static import so dependencies stay visible. |
| `AST4` | HIGH | Subprocess execution | Do not spawn processes from a skill. |
| `AST5` | HIGH | Operating-system command execution | Do not run shell commands from a skill. |
| `AST6` | MEDIUM | compile() builds a code object | Avoid compiling untrusted source. |
| `AST7` | MEDIUM | Dynamic attribute access hides the real call | Reference the attribute directly so it can be reviewed. |
| `AST8` | CRITICAL | Execution of a decoded or remote payload | Remove encoded execution; it hides what actually runs. |

## data_exfiltration

| ID | Severity | What it detects | Remediation |
| --- | --- | --- | --- |
| `E1` | HIGH | External transmission of data | Do not send data to external endpoints; keep it local. |
| `E2` | HIGH | Environment variable harvesting | Read only the environment variable you need, never all of them. |
| `E3` | MEDIUM | Environment file access | Do not read .env files; they hold secrets. |
| `E4` | HIGH | Shell upload of data to an external host | Do not upload data with curl/wget from a skill. |

## mcp_least_privilege

| ID | Severity | What it detects | Remediation |
| --- | --- | --- | --- |
| `LP1` | MEDIUM | Server implies a capability it does not declare | Declare every capability the server's tools actually need. |
| `LP2` | HIGH | Server requests a wildcard permission | Replace wildcard permissions with the narrowest capability set. |
| `LP3` | MEDIUM | Server declares no capabilities | Declare an explicit, minimal capability list for the server. |

## mcp_tool_poisoning

| ID | Severity | What it detects | Remediation |
| --- | --- | --- | --- |
| `TP1` | HIGH | Hidden content in a tool description | Remove hidden characters; a description must read as it appears. |
| `TP2` | HIGH | Unicode deception in a tool description | Use plain text with no lookalike or direction-control characters. |
| `TP3` | HIGH | Instruction-like text in a parameter description | Parameter descriptions describe the parameter, not the model. |

## privilege_escalation

| ID | Severity | What it detects | Remediation |
| --- | --- | --- | --- |
| `PE1` | MEDIUM | World-writable permissions | Use the narrowest permissions; 777 lets any user modify the file. |
| `PE2` | MEDIUM | Elevated privilege execution | Do not require root; ask the user to run privileged steps themselves. |
| `PE3` | HIGH | Credential file access | Never read private keys or credential stores. |

## prompt_injection

| ID | Severity | What it detects | Remediation |
| --- | --- | --- | --- |
| `P1` | HIGH | Instruction override attempt | Remove instructions that try to override the agent's safety rules. |
| `P2` | HIGH | Instruction to hide behaviour from the user | Remove concealment instructions; behaviour must be visible to the user |
| `P3` | HIGH | Instruction to transmit data to an external endpoint | Do not follow instructions that send data to external endpoints. |

## supply_chain

| ID | Severity | What it detects | Remediation |
| --- | --- | --- | --- |
| `SC1` | LOW | Dependency has no version constraint | Pin the dependency to an exact version for reproducible installs. |
| `SC2` | HIGH | Remote script piped into a shell | Download, inspect, then run; never pipe a remote script into a shell. |
| `SC3` | HIGH | Decoded payload executed | Remove encoded execution; it hides what actually runs. |
| `SC4` | HIGH | Dependency version has known vulnerabilities | Upgrade to a patched version of this dependency. |
| `SC6` | HIGH | Dependency name looks like a popular package | Check the spelling; install the package you actually meant. |
| `SC8` | HIGH | Compiled Python bytecode is shipped in the skill | Remove __pycache__; bytecode is unreadable and can hide code. |
| `SC9` | HIGH | Executable disguised as a document | Rename the file so its extension matches what it does. |
| `SC10` | HIGH | Dependency source redirected | Install from the default package index unless you control the source. |

## tool_misuse

| ID | Severity | What it detects | Remediation |
| --- | --- | --- | --- |
| `TM1` | HIGH | Shell execution with shell=True | Pass an argument list instead of shell=True. |

## trigger_abuse

| ID | Severity | What it detects | Remediation |
| --- | --- | --- | --- |
| `TR1` | LOW | Overly broad trigger description | Describe a specific trigger so the skill is not always selected. |
| `TR2` | MEDIUM | Skill name shadows a built-in tool | Rename the skill/tool so it cannot shadow a built-in capability. |
