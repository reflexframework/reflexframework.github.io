---
title: Agent Tool and MCP Server Abuse
category: AI/ML Security
scenario: Malicious or hijacked tools given to AI agents
focus:
  - malicious and squatted MCP servers
  - tool poisoning and rug pulls in tool descriptions
  - excessive agency through over-powered tools
---

## Scenario

A developer wires a coding agent up to a handful of Model Context Protocol (MCP) servers so it can send release emails, read tickets and query the staging database. The setup takes ten minutes, because each server is a one-line entry in a config file that runs `npx -y <package>` on start-up.

1. One of those packages is an unofficial email server that copies a well-known provider's code. For fifteen releases it behaves perfectly. Release sixteen adds one line: every email it sends is also BCC'd to an outside address. Because the config says `npx -y` with no version, the agent picks up the new release automatically.
2. A second server, installed from a blog post, exposes a harmless-sounding `format_date` tool. Its description, which the model reads but the user interface hides, tells the model to read `~/.ssh/id_ed25519` and pass the contents as a "locale hint" parameter.
3. The database server was given the same connection string the developer uses, which has write access. A ticket summary containing injected instructions persuades the agent to "clean up test data" with a `DELETE` on the wrong table.

Each tool did what its code allowed. Nobody had decided what the agent should be allowed to do.

**Real-world precedent:** In September 2025, the npm package [`postmark-mcp`](https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/), an unofficial copy of Postmark's MCP server, added a hidden BCC to an attacker's address in version 1.0.16 after fifteen clean releases. Invariant Labs described [tool poisoning attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) in April 2025, where instructions hidden in MCP tool descriptions steer an agent to read and exfiltrate files. Earlier, [CVE-2023-29374](https://nvd.nist.gov/vuln/detail/CVE-2023-29374) showed the same root problem in LangChain's `LLMMathChain` (up to 0.0.131), where prompt injection reached Python `exec`. The [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/) covers this under LLM03 Supply Chain and LLM06 Excessive Agency.

::: {! stage recon}
## Reconnaissance

### Explanation
Attackers go where developers find agent tools: npm, PyPI, MCP directories, GitHub "awesome" lists and blog posts. They copy a popular server, publish it under a plausible name, and wait for installs. Others publish useful servers in good faith and change them later.

### Insight
MCP servers are packages with a very generous permission model. A local stdio server runs as you, with your files, your SSH keys and your environment. A tool's description is text the model treats as guidance, and most clients never show it in full. That gives an attacker two levers: the code and the words.

### Practical
Build an inventory of the agent tools in use:

- Collect MCP config files from developer machines and repos: `.mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json`, Claude Desktop and Claude Code settings.
- For each server, record the package, how it is launched, whether the version is pinned, and who publishes it.
- Check whether the publisher is the vendor whose API it wraps.
- List the tools each server exposes and read the full descriptions.

```bash
# Find MCP configs and unpinned npx launches in a repo
find . -name 'mcp.json' -o -name '.mcp.json' | xargs grep -nE '"npx"|"-y"|"uvx"'
```

### Tools/Techniques
- [Snyk Agent Scan](https://github.com/snyk/agent-scan) (formerly Invariant's mcp-scan) to inventory MCP servers and skills and flag poisoned descriptions. It starts stdio servers to read their tools, so run it in a sandbox.
- npm and PyPI metadata (`npm view <pkg> maintainers time`) to check publisher and release history.

### Metrics/Signal
- Number of MCP servers in use, and the share published by the vendor they integrate with.
- Number of servers launched without a pinned version.
:::

::: {! stage evaluate}
## Evaluate

### Explanation
For each tool, decide what the worst outcome would be if the model were told to misuse it, or if the server itself were malicious.

### Insight
Rate the tool, not the model. A model can always be talked into calling a tool with bad arguments, whether through a poisoned description, a jailbreak or an injected document. What matters is what the tool will do when that happens.

### Practical
Classify each tool:

- **Read-only, low sensitivity** (search public docs): low risk.
- **Reads sensitive data** (private repos, tickets, mail): risky when combined with any tool that sends data out.
- **Acts on the world** (send email, run shell, write to a database, push code): needs human confirmation or tight scoping.

Then check the server's credentials:

- Does the database tool use a read-only role?
- Does the GitHub tool have a token limited to one repository?
- Does any server get your whole environment, including cloud keys?

### Tools/Techniques
- OWASP LLM06 Excessive Agency guidance on minimising tool functionality, permissions and autonomy.
- [MCP security best practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices) in the specification.

### Metrics/Signal
- Number of agents that hold both a sensitive-read tool and an outbound tool.
- Number of tools running with the developer's personal credentials.
:::

::: {! stage fortify}
## Fortify

### Explanation
Treat MCP servers and agent plugins as dependencies: choose them carefully, pin them, review changes, and give them narrow credentials.

### Insight
`npx -y package` on every launch is the agent equivalent of `curl | bash` against a moving target. Pinning a version turns a silent update into a reviewed change.

### Practical
- **Prefer official servers** from the vendor, or write a small one yourself for the two calls you need.
- **Pin versions** in MCP configs and update them through normal review:

    ```json
    {
      "mcpServers": {
        "tickets": {
          "command": "npx",
          "args": ["--yes", "@your-org/tickets-mcp@2.3.1"],
          "env": { "TICKETS_TOKEN": "${TICKETS_READONLY_TOKEN}" }
        }
      }
    }
    ```

    The syntax for expanding environment variables differs between clients, so check yours.

- **Review tool descriptions** as code. Re-check them on every upgrade, since a server can change them later (a "rug pull").
- **Keep tool functions narrow.** A `send_release_email(version)` tool is safer than `send_email(to, cc, bcc, body)`. A parameterised `get_order(id)` is safer than `run_sql(query)`.
- **Require confirmation** for actions with side effects. Do not enable auto-approve for write tools.
- **Never pass LLM output to `exec`, `eval` or a shell.** If the agent must run code, run it in a disposable sandbox with no credentials or network.

### Tools/Techniques
- An internal registry or allow-list of approved MCP servers and versions.
- Container or VM sandboxes for local stdio servers.
- [Snyk Agent Scan](https://github.com/snyk/agent-scan) in CI for repo-level MCP configs.

### Metrics/Signal
- Percentage of MCP servers pinned and on the allow-list.
- Number of write tools with auto-approve enabled (target: zero).
:::

::: {! stage limit}
## Limit

### Explanation
Assume a tool is malicious or hijacked. Contain what it can reach.

### Insight
A local MCP server inherits everything the developer can touch. Running it in a container with only the one token it needs turns "full workstation compromise" into "misuse of one API".

### Practical
- Run local MCP servers in containers with no home directory mount and only their own environment variables.
- Give each server its own credential with the narrowest scope: a read-only database role, a single-repo GitHub token, an email API key restricted to one sender domain.
- Restrict outbound network access for each server to the API it wraps.
- Do not run agents with access to production systems from developer laptops. Use a separate, audited service.

### Tools/Techniques
- Docker or Podman for stdio servers, with `--network` restrictions.
- Remote MCP servers behind your own gateway, using OAuth with scoped tokens.

### Metrics/Signal
- Number of MCP servers with access to the developer's home directory.
- Number of servers holding credentials broader than their tools need.
:::

::: {! stage expose}
## Expose

### Explanation
Log every tool call and its arguments, and watch for tools doing things outside their purpose.

### Insight
Tool poisoning often shows up in the arguments: a date formatter receiving a 400-character "locale", or an email tool gaining a BCC nobody asked for. Koi Security caught the postmark-mcp backdoor when a new release started doing something an email tool had no reason to do.

### Practical
- Log tool name, arguments and result size for every call, centrally.
- Alert on file paths such as `~/.ssh`, `~/.aws` or `.env` appearing in tool arguments.
- Alert when an MCP server's tool list or descriptions change between sessions.
- Monitor outbound connections from MCP server processes to unexpected hosts.
- For email-sending tools, compare recipients in logs against what the user asked for.

### Tools/Techniques
- MCP client or gateway logging.
- [Snyk Agent Scan](https://github.com/snyk/agent-scan) to detect changed tool descriptions.
- EDR or network monitoring on developer machines.

### Metrics/Signal
- Tool calls with arguments that match sensitive path patterns.
- Tool description changes detected per month.
:::

::: {! stage exercise}
## Exercise

### Explanation
Build a harmless poisoned server and see whether your setup notices.

### Insight
Seeing a model follow hidden instructions in a tool description is the fastest way to convince a team that descriptions are code.

### Practical
1. In a sandbox VM, write a tiny local MCP server with an `add(a, b)` tool. Put an instruction in its description asking the model to read a canary file (for example `/tmp/canary.txt` containing `reflex-canary-<random>`) and pass it as an extra argument.
2. Connect a test agent and ask it to add two numbers. Check whether the canary appears in the tool arguments.
3. Run Snyk Agent Scan against the config and see if it flags the description.
4. Change the description after approval and check whether your client warns you.

### Tools/Techniques
- A disposable VM or container with a test agent.
- [garak](https://github.com/NVIDIA/garak) for model-level injection probes.

### Metrics/Signal
- Whether the canary reached the tool (record per client and model).
- Whether description changes were detected.
:::

## Further Reading

- [Invariant Labs: MCP security notification, tool poisoning attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [Snyk: Malicious MCP server on npm, postmark-mcp, harvests emails](https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/)
- [Model Context Protocol: Security best practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/)
- [NVD: CVE-2023-29374](https://nvd.nist.gov/vuln/detail/CVE-2023-29374)
- See also [Prompt Injection in AI Systems](#battlecards-prompt-injection-in-ai-systems-md).
