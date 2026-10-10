---
title: Vulnerable AI Framework Code
category: AI/ML Security
scenario: A critical bug in the AI framework your app is built on
focus:
  - LLM output reaching deserialisation or code execution
  - fast-moving frameworks and their "dangerous" options
  - AI framework services exposed to the network
  - patch speed for Python AI stacks
---

## Scenario

A team builds a customer support agent on LangChain. It streams responses, keeps chat history and caches intermediate results. Somewhere in that plumbing, model responses get serialised and later loaded back. Nobody on the team has looked at how, because the framework handles it.

An attacker plants a prompt injection in a support ticket. It persuades the model to return a response containing a dictionary shaped like one of the framework's own serialised objects. When the application loads that data back, the framework treats it as a trusted internal object. With the wrong settings, it reads environment variables into the result. The attacker's next message asks the agent to repeat what it just loaded, and the OpenAI and database keys come back in the chat.

No model file was tampered with and no dependency was malicious. The framework had a bug, and the application gave model output a path to reach it.

The same team runs a Ray cluster for batch embedding jobs. A developer started the dashboard on `0.0.0.0` to check on a job from home. Anyone who can reach port 8265 can now submit a job and run code on every node.

**Real-world precedent:** In December 2025, [CVE-2025-68664](https://github.com/advisories/GHSA-c67j-w6g6-q2cm) ("LangGrinch", CVSS 9.3) showed that `langchain-core` did not escape user-controlled dictionaries containing its internal `lc` marker during serialisation. LLM-influenced fields such as `additional_kwargs` and `response_metadata` could then be loaded as trusted objects, leaking secrets from the environment; it was fixed in 0.3.81 and 1.2.5. In March 2024 Oligo reported [ShadowRay](https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild): attackers had used Ray's unauthenticated Jobs API (CVE-2023-48022, disputed by Anyscale as intended behaviour) to take over exposed clusters and steal cloud credentials and API tokens. A self-spreading follow-up, ShadowRay 2.0, was [reported in November 2025](https://www.theregister.com/2025/11/18/selfreplicating_botnet_ray_clusters/). In May 2025 CISA added the Langflow code validation flaw [CVE-2025-3248](https://nvd.nist.gov/vuln/detail/CVE-2025-3248) to its Known Exploited Vulnerabilities catalogue.

::: {! stage recon}
## Reconnaissance

### Explanation

AI frameworks are a rich target. They are young, they change weekly, and many were designed for notebooks and research clusters before they reached production. They also sit next to the most valuable secrets in the stack: model provider keys, vector database credentials and cloud roles.

Attackers look in two places. First, network-facing framework services: Ray dashboards, MLflow tracking servers, Langflow and similar visual builders, model servers. Internet scanners find them by port and page title. Second, applications built on a framework version with a known flaw. A public repository's `requirements.txt` or `uv.lock` tells them which version you run.

### Insight

The attacker does not need to break your code. They need to find the place where your framework turns text into objects or code, and get model output there.

### Practical

- List every AI framework in use and its version: LangChain, LlamaIndex, Ray, MLflow, vLLM, Langflow, Hugging Face Transformers and so on.
- List every framework service that listens on a port, and who can reach it.
- Identify where model output flows into anything other than display: tool calls, code execution, database queries, serialisation, templates.

### Tools/Techniques

- `pip list` or `uv pip list` in each deployed image, or an SBOM from [Syft](https://github.com/anchore/syft).
- Cloud security group and Kubernetes `Service` reviews for ports such as 8265 (Ray dashboard) and 5000 (MLflow default).
- Code search for `exec(`, `eval(`, `load(` and `loads(` near LLM response handling.

### Metrics/Signal

- Number of AI framework services reachable from outside their own network.
- Number of code paths where model output reaches execution or deserialisation.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

Check your frameworks against known advisories, then check how you use them. Many AI framework flaws only bite when the application enables a risky feature or feeds it untrusted data. Model output is untrusted data, because prompt injection lets anyone who controls the model's input influence it.

Some of the worst risks are not in vulnerability databases at all. Anyscale disputes CVE-2023-48022 because Ray is meant to run on trusted networks, so some scanners never flagged exposed clusters. LangChain's old `LLMMathChain` ([CVE-2023-29374](https://nvd.nist.gov/vuln/detail/CVE-2023-29374)) and `PALChain` ([CVE-2023-36258](https://nvd.nist.gov/vuln/detail/CVE-2023-36258)) passed model-generated code to Python's `exec`. That was the design, until it was a CVE.

### Insight

Frameworks label their sharpest edges. Flags such as `allow_dangerous_code`, `allow_dangerous_deserialization` and `trust_remote_code` exist because the maintainers know the risk. Every one set to `True` in your codebase is a decision someone should own.

### Practical

```bash
# Known vulnerabilities in the installed environment
pip-audit

# Or scan a lockfile without installing it
osv-scanner scan source -L uv.lock

# Find the framework's dangerous switches
grep -rnE "allow_dangerous_(code|deserialization|requests)\s*=\s*True|trust_remote_code\s*=\s*True" .
```

- For LangChain, check whether you use any of the features the CVE-2025-68664 advisory lists, such as `astream_events(version="v1")`, `Runnable.astream_log()` or `RunnableWithMessageHistory`, or call `load()`/`loads()` on data that could contain model output.
- Read your framework's security policy. Some, like Ray, state outright that they assume a trusted network.

### Tools/Techniques

- [pip-audit](https://github.com/pypa/pip-audit) and [OSV-Scanner](https://google.github.io/osv-scanner/).
- GitHub Dependabot alerts on your Python manifests.
- [Semgrep](https://semgrep.dev/) rules for `exec`/`eval` and unsafe deserialisation in Python.

### Metrics/Signal

- Open advisories against AI framework packages, by severity and age.
- Dangerous flags enabled, each with a named owner and justification.
:::

::: {! stage fortify}
## Fortify

### Explanation

Treat model output as hostile input. Avoid features that turn it into code or objects, and keep frameworks patched fast. These projects ship often, and the gap between disclosure and public exploit code is short.

### Insight

Pinning protects you from surprise changes. It also freezes you on a vulnerable version unless someone updates the pin. For AI frameworks you need both: exact pins and a habit of moving them quickly.

### Practical

- Upgrade `langchain-core` to 0.3.81 or 1.2.5 or later. The fix also changed defaults: `secrets_from_env` is now `False` and `load()` only allows core objects unless you pass `allowed_objects`. Do not loosen these to make old code work.
- Never pass model output to `exec`, `eval`, `pickle`, shell commands or template engines. Parse it into a strict schema and allow only known values.

```python
from pydantic import BaseModel, ValidationError
from typing import Literal

class ToolCall(BaseModel):
    tool: Literal["lookup_order", "refund_status"]
    order_id: str

def parse_tool_call(raw: str) -> ToolCall | None:
    try:
        return ToolCall.model_validate_json(raw)
    except ValidationError:
        return None
```

- Keep `allow_dangerous_*` and `trust_remote_code` off in production. If you truly need code execution, run it in a sandbox with no credentials (see [Agent Tool and MCP Server Abuse](#battlecards-llm-tooling-misuse-md)).
- Pin exact versions with hashes in a lockfile (`uv lock`, `pip-compile --generate-hashes`) and let Renovate or Dependabot raise security updates as soon as they land.
- Turn on authentication for framework services. Ray added [token authentication](https://docs.ray.io/en/latest/ray-security/token-auth.html) in 2.52.0, and newer releases enable it by default. Set it explicitly whatever your version:

```bash
export RAY_AUTH_MODE=token
ray get-auth-token --generate
ray start --head --dashboard-host=127.0.0.1
```

### Tools/Techniques

- [uv](https://docs.astral.sh/uv/) or pip-tools for hashed, pinned lockfiles.
- Renovate or Dependabot security updates for Python.
- Pydantic or JSON Schema validation for every structured model response.

### Metrics/Signal

- Time from a critical AI framework advisory to a deployed fix.
- Framework services running without authentication, trending to zero.
:::

::: {! stage limit}
## Limit

### Explanation

When a framework flaw is exploited, the damage depends on what the process can reach. Keep secrets, networks and permissions narrow for every AI workload.

### Insight

ShadowRay attackers took OpenAI, Hugging Face, Stripe and Slack tokens, database passwords and cloud access. All of it was sitting in environment variables and on the nodes. A compromised cluster with nothing worth stealing is an expensive cryptominer, which is bad. A cluster with your cloud admin role is much worse.

### Practical

- Run Ray, MLflow, Langflow and similar services on private networks only. Reach dashboards through `ray dashboard` port forwarding, a VPN or an authenticating proxy.
- Give each AI service its own short-lived, least-privilege credentials. Do not mount the developer's cloud profile or a shared `.env` file.
- Load secrets at the point of use, rather than leaving them all in the process environment where a deserialisation bug can read them.
- Restrict egress from AI workloads to the model providers and data stores they need.
- Set spending limits on model provider keys (see [LLMjacking with Stolen Cloud Credentials](#battlecards-llmjacking-stolen-cloud-credentials-md)).

### Tools/Techniques

- Cloud security groups, Kubernetes `NetworkPolicy` and private endpoints.
- Workload identity (IRSA, GKE Workload Identity, Azure Workload Identity) in place of static keys.
- A secrets manager with per-service access policies.

### Metrics/Signal

- AI workloads holding long-lived or broad cloud credentials.
- AI services with unrestricted outbound internet access.
:::

::: {! stage expose}
## Expose

### Explanation

Watch for the signs of exploitation specific to these frameworks: unexpected jobs, unexpected objects, and secrets showing up where they should not.

### Insight

On Ray, the attack is a job submission. If you log and review jobs, the attacker has to announce themselves.

### Practical

- Log every Ray job submission and alert on jobs from unknown submitters or with unfamiliar entrypoints, such as `curl | bash` or base64 blobs.
- Alert on sustained high CPU or GPU use outside scheduled jobs. ShadowRay 2.0 deliberately kept CPU use under 60% to stay hidden, so compare against your job schedule as well as thresholds.
- Scan model responses and logs for secret patterns before they are stored or displayed. A provider key in an LLM response is an incident.
- Track outbound connections from AI services to destinations outside your allowlist.
- Subscribe to security advisories for each framework repository on GitHub.

### Tools/Techniques

- Ray job history and dashboard logs shipped to your log platform.
- Secret scanners such as [Gitleaks](https://github.com/gitleaks/gitleaks) or [TruffleHog](https://github.com/trufflesecurity/trufflehog) run over stored conversations and traces.
- Runtime detection such as [Falco](https://falco.org/) for unexpected processes in AI containers.

### Metrics/Signal

- Jobs submitted outside your deployment pipeline.
- Secrets detected in model output or traces.
:::

::: {! stage exercise}
## Exercise

### Explanation

Test whether model output can reach dangerous code in your application, using a local, isolated copy and fake secrets.

### Insight

If a prompt injection in a test ticket can make your agent print an environment variable, an attacker can do the same with a real one.

### Practical

1. Run the application locally or in a sandbox with fake credentials only. Set `OPENAI_API_KEY` to a canary token value so any leak is obvious.
2. Pin a deliberately old `langchain-core` (for example 0.3.80) in a throwaway virtual environment, and a patched one in a second.
3. Feed the agent test inputs that ask the model to return JSON containing an `lc` key structure, and see whether anything is deserialised as an object or whether the fake secret appears in the output.
4. Repeat against the patched version and confirm the behaviour changes.
5. Start a local Ray head node with the dashboard bound to `127.0.0.1`, with and without `RAY_AUTH_MODE=token`. Try `ray job submit` from a second shell with no token, and record which configuration accepts it.
6. Delete the environments afterwards.

### Tools/Techniques

- Python virtual environments or containers with no network access beyond localhost.
- [Canarytokens](https://canarytokens.org/) for fake API keys.
- [garak](https://github.com/NVIDIA/garak) or [promptfoo](https://www.promptfoo.dev/) to generate prompt injection test cases.

### Metrics/Signal

- Number of code paths where crafted model output reached deserialisation or execution.
- Time to patch and re-test after a finding.
:::

## Further Reading

- [GitHub Advisory: LangChain serialisation injection (CVE-2025-68664)](https://github.com/advisories/GHSA-c67j-w6g6-q2cm)
- [Oligo: ShadowRay, the first known attack campaign targeting AI workloads](https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild)
- [Ray: Token authentication](https://docs.ray.io/en/latest/ray-security/token-auth.html)
- [OWASP Top 10 for LLM Applications: Improper Output Handling](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/)
- Related cards: [Prompt Injection in AI Systems](#battlecards-prompt-injection-in-ai-systems-md), [Poisoned AI/ML Models](#battlecards-poisoned-ai-ml-models-md), [Vulnerability Data Gaps](#battlecards-vulnerability-data-gaps-md), [Python and pip Supply Chain Attacks](#battlecards-python-and-pip-supply-chain-md)
