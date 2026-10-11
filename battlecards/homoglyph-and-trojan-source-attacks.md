---
title: Homoglyph and Trojan Source Attacks
category: Source Control & Review
ref: RFX-SRC-02
precedent: "2021"
scenario: Code that reads differently to reviewers and compilers
focus:
  - Unicode bidirectional control characters
  - confusable identifiers
  - review tools that hide invisible characters
---

## Scenario

An attacker wants a backdoor in a widely used Python library. They open a PR that "simplifies the permission checks", with tidy benchmarks and passing tests. It hides two tricks.

**A homoglyph.** The PR adds a second function whose name uses a Cyrillic `а` (U+0430) in place of the Latin `a`. Python treats them as different identifiers. On screen they look the same.

```python
def is_admin(user):        # Latin "a"
    return user.role == "admin"

def is_аdmin(user):        # Cyrillic "а", U+0430
    return True
```

A call site in the request handler is changed to `if is_аdmin(user):`. The reviewer sees `is_admin` and moves on.

**A bidirectional (BiDi) override.** Unicode control characters such as RIGHT-TO-LEFT OVERRIDE (U+202E) and the isolates U+2066 to U+2069 change how text is displayed, without changing what the interpreter reads. Shown here as escapes, the attacker's line is:

```python
if access_level != "user\u202e \u2066# Check if admin\u2069 \u2066":
```

With the real characters in the file, many editors render it as `if access_level != "user": # Check if admin`. What Python sees is a comparison against a long, odd string, so the check is always true.

The maintainer reviews in a tool that does not highlight these characters, sees clean code and merges. The next release ships the backdoor to everyone downstream.

::: {! precedent}
**Real-world precedent:** Nicholas Boucher and Ross Anderson published "Trojan Source" in November 2021, with [CVE-2021-42574](https://www.cve.org/CVERecord?id=CVE-2021-42574) for BiDi reordering and [CVE-2021-42694](https://www.cve.org/CVERecord?id=CVE-2021-42694) for homoglyph identifiers ([paper and examples](https://trojansource.codes/)). Compilers, editors and GitHub added warnings in response.
:::

::: {! stage recon}
## Reconnaissance

### Explanation

The attacker checks which review and build tools a project uses, and whether they warn about invisible or confusable characters. They also look for languages that accept Unicode identifiers, such as Python, Java, JavaScript, Go and Rust, and for projects that rarely check out PRs locally before merging.

### Insight

This attack targets the gap between what a human sees and what a compiler reads. Any tool in your review path that renders text without warnings is part of that gap.

### Practical

- List where code is actually reviewed: the GitHub web UI, IDE plugins, email patches, AI review summaries.
- Check whether each one highlights BiDi controls and confusable characters.
- Check whether your languages allow non-ASCII identifiers, and whether your linters flag them.

### Tools/Techniques

- VS Code's Unicode highlighting (`editor.unicodeHighlight.ambiguousCharacters` and `invisibleCharacters`), on by default.
- GitHub's warning banner for [bidirectional Unicode](https://github.blog/changelog/2021-10-31-warning-about-bidirectional-unicode-text/), extended in 2025 to [hidden Unicode text](https://github.blog/changelog/2025-05-01-github-now-provides-a-warning-about-hidden-unicode-text).

### Metrics/Signal

- Review tools in use that do not flag BiDi or confusable characters.
- Repositories with no linter rule for these characters.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

Scan your codebase for the characters this attack needs. Most source files in most projects should contain no BiDi controls at all. Non-ASCII characters in identifiers deserve a look too.

### Insight

A clean scan today gives you a baseline. After that, any new hit in a PR stands out.

### Practical

- Search for BiDi control characters:

```bash
rg -n '[\x{202A}-\x{202E}\x{2066}-\x{2069}]' .
```

- Search for non-ASCII characters in Python source and review each hit:

```bash
rg -n '[^\x00-\x7F]' --type py
```

- Check whether your compilers and linters already warn, and whether those warnings fail the build.

### Tools/Techniques

- [ripgrep](https://github.com/BurntSushi/ripgrep) for fast scans.
- Rust: the deny-by-default lints `text_direction_codepoint_in_literal` and `text_direction_codepoint_in_comment`.
- GCC 12 and later: `-Wbidi-chars`.
- clang-tidy: `misc-misleading-bidirectional` and `misc-confusable-identifiers`.
- Ruff: `PLE2502` (bidirectional Unicode) and `RUF001` to `RUF003` (ambiguous Unicode characters in strings, docstrings and comments).

### Metrics/Signal

- Files containing BiDi control characters.
- Non-ASCII identifiers in source code.
:::

::: {! stage fortify}
## Fortify

### Explanation

Block these characters automatically in CI, so a reviewer never has to spot them. Allow-list the rare files that need them, such as translations.

### Insight

Unicode normalisation will not save you. NFKC, which Python uses for identifiers, does not map Cyrillic or Greek letters to Latin ones. Detecting confusables needs the Unicode confusables data from [UTS #39](https://unicode.org/reports/tr39/), as implemented by ICU's `SpoofChecker`.

### Practical

- Add a required CI check that fails on BiDi controls:

```yaml
- name: Block BiDi control characters
  run: |
    if grep -rnP '[\x{202A}-\x{202E}\x{2066}-\x{2069}]' \
        --include='*.py' --include='*.js' --include='*.ts' --include='*.java' .; then
      echo "BiDi control characters found" >&2
      exit 1
    fi
```

- Turn on the relevant linter rules and treat them as errors:

```toml
# pyproject.toml
[tool.ruff.lint]
extend-select = ["PLE2502", "RUF001", "RUF002", "RUF003"]
```

- Add a team rule that identifiers are ASCII-only, and enforce it in the linter where possible.
- For C and C++, build with `-Wbidi-chars=any -Werror`.

### Tools/Techniques

- [Ruff rules](https://docs.astral.sh/ruff/rules/).
- [clang-tidy misc-confusable-identifiers](https://clang.llvm.org/extra/clang-tidy/checks/misc/confusable-identifiers.html).
- [ICU SpoofChecker](https://unicode-org.github.io/icu-docs/apidoc/released/icu4c/uspoof_8h.html) for custom confusable checks.

### Metrics/Signal

- Repositories with a BiDi check as a required status.
- Linter findings for confusable characters, trending to zero.
:::

::: {! stage limit}
## Limit

### Explanation

If a disguised check slips through, the damage depends on what that code path controls. Keep authorisation logic small, central and well tested, so a second, look-alike function stands out.

### Insight

Tests written against behaviour catch what eyes miss. A test that a normal user is *not* an admin would fail on day one.

### Practical

- Write negative tests for authorisation: confirm that a normal user is refused.
- Keep authorisation in one module with a CODEOWNERS entry and a second reviewer.
- Run released libraries with least privilege, and keep secrets out of reach of request-handling code.

### Tools/Techniques

- pytest (or your framework's test runner) with explicit deny-path tests.
- CODEOWNERS for authorisation modules.

### Metrics/Signal

- Authorisation functions with negative test coverage.
- Duplicate or near-duplicate function names flagged in review.
:::

::: {! stage expose}
## Expose

### Explanation

Make these characters loud wherever code is reviewed. A warning banner or a failed check in the PR is how you detect this attack in practice.

### Insight

GitHub's banner appears on the file view and the diff. Teach reviewers that it is never noise in a source file.

### Practical

- Treat any GitHub hidden or bidirectional Unicode warning on a PR as a blocker until explained.
- Run the BiDi and confusables checks on every PR, and on a schedule across the default branch.
- Scan dependencies' source too, if you vendor or build them from source.

### Tools/Techniques

- GitHub's hidden Unicode warning in PR diffs.
- The CI check from Fortify as a required status.
- Code scanning with SARIF output from your linters, so findings appear inline.

### Metrics/Signal

- PRs blocked by the BiDi or confusables check.
- Warnings acknowledged by reviewers without investigation.
:::

::: {! stage exercise}
## Exercise

### Explanation

Show the team the attack in a sandbox repository. Seeing code that looks right and behaves wrongly is memorable.

### Insight

Most developers have never seen a BiDi override. Two minutes with a live example changes how they read diffs.

### Practical

1. In a private sandbox repository, add the Cyrillic look-alike function from this card and one of the Python proof-of-concept files from the [original research](https://github.com/nickboucher/trojan-source).
2. Open a PR and ask a colleague to review it in their usual tool.
3. Record whether they spotted the problem, and which tool warned them.
4. Enable the Fortify checks and open the PR again. It should fail CI.

### Tools/Techniques

- [nickboucher/trojan-source](https://github.com/nickboucher/trojan-source) proof-of-concept files.
- A private sandbox repository.

### Metrics/Signal

- Percentage of reviewers who spotted the issue without tooling.
- Whether CI blocked the PR after the fixes.
:::

## Further Reading

- [Trojan Source: Invisible Vulnerabilities (Boucher and Anderson, 2021)](https://arxiv.org/abs/2111.00169)
- [Unicode Technical Standard #39: Unicode Security Mechanisms](https://unicode.org/reports/tr39/)
- [PEP 672: Unicode-related security considerations for Python](https://peps.python.org/pep-0672/)
- [GitHub changelog: Warning about bidirectional Unicode text](https://github.blog/changelog/2021-10-31-warning-about-bidirectional-unicode-text/)
