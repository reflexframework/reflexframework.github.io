---
title: AI Dependency Typosquatting and Slopsquatting
category: AI/ML Security
scenario: Malicious look-alike ML packages, hallucinated names and booby-trapped models
focus:
  - typosquatted and confused ML packages on PyPI
  - slopsquatting of LLM-hallucinated package names
  - malicious pickle models on Hugging Face
---

## Scenario

An ML team is moving fast on a computer vision prototype. Three things go wrong in the same sprint.

1. A developer asks a coding assistant how to download weights from the Hub. The answer says `pip install huggingface-cli`. That name sounds right, but the real CLI ships in `huggingface_hub`. Someone has registered the hallucinated name on PyPI, and its install-time code reads `~/.cache/huggingface/token` and `~/.aws/credentials`.
2. The training job installs nightly wheels with `--extra-index-url`. An internal helper package, `vision-aug-internal`, is not on the private index for a day after a rename. pip finds a package with the same name on PyPI and installs that instead.
3. A notebook loads `torch.load("pytorch_model.bin")` from a Hugging Face repo whose name differs from the official one by a single character. The pickle inside opens a reverse shell on the shared GPU box.

None of these needs a zero-day. Each one relies on a developer, or an AI assistant, choosing a name that looks right.

**Real-world precedent:** In December 2022, a [malicious `torchtriton` on PyPI](https://pytorch.org/blog/compromised-nightly-dependency/) was installed by PyTorch nightly users because PyPI took precedence over PyTorch's own index. In December 2024, [`ultralytics` 8.3.41, 8.3.42, 8.3.45 and 8.3.46](https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/) shipped a cryptominer after its GitHub Actions build and a leftover PyPI token were compromised. In February 2025, ReversingLabs found [nullifAI models on Hugging Face](https://www.reversinglabs.com/blog/rl-identifies-malware-ml-model-hosted-on-hugging-face) that hid reverse shells in deliberately broken pickles to evade Picklescan. Bar Lanyado first documented LLM package hallucinations at Vulcan Cyber in 2023; his later [empty `huggingface-cli` package](https://www.lasso.security/blog/ai-package-hallucinations), registered under a name models kept inventing, drew more than 30,000 downloads in three months.

::: {! stage recon}
## Reconnaissance

### Explanation
Attackers study which names ML developers type, copy and get suggested. They look at popular frameworks (torch, transformers, ultralytics, langchain), the extra indexes in public `requirements.txt` files, internal package names leaked in tracebacks, and names that LLMs keep inventing.

### Insight
Slopsquatting is typosquatting where the typo comes from a model. A [USENIX Security 2025 study](https://www.usenix.org/conference/usenixsecurity25/presentation/spracklen) generated 576,000 code samples from 16 models and found that 19.7% of recommended packages did not exist, producing over 205,000 unique fake names. Many recurred when the same prompt was rerun, which makes them predictable enough to register. This card is about invented package *names* that an attacker can claim. Assistants also invent *versions* of real packages and suggest stale or compromised releases; that quieter problem has its own card, [AI dependency recommendations](#battlecards-ai-dependency-recommendations-md).

### Practical
Look for the names an attacker would target in your own code:

- Grep your `requirements*.txt`, `pyproject.toml` and notebooks for `--extra-index-url`. Every package that comes from the extra index is a confusion candidate.
- List internal package names and check whether each one is registered on PyPI by someone else.
- List every `from_pretrained()`, `hf_hub_download()` and `torch.load()` call, and the repo IDs they reference.
- Ask your coding assistant the questions your team asks, and check every package it suggests exists and is the one you meant.

```bash
# Find extra indexes and model loads across a repo
grep -rn --include='*.txt' --include='*.toml' --include='*.cfg' -- '--extra-index-url' .
grep -rnE 'from_pretrained\(|hf_hub_download\(|torch\.load\(' --include='*.py' --include='*.ipynb' .
```

### Tools/Techniques
- [garak](https://github.com/NVIDIA/garak) `packagehallucination` probes to measure how often your chosen model invents package names.
- [OSV-Scanner](https://github.com/google/osv-scanner) to check pinned dependencies against known malicious package reports in OSV.
- PyPI's JSON API (`https://pypi.org/pypi/<name>/json`) to check who published a name and when.

### Metrics/Signal
- Number of internal package names that are unregistered (or registered by strangers) on PyPI.
- Number of model repos loaded by name without a pinned revision.
:::

::: {! stage evaluate}
## Evaluate

### Explanation
Check how your installs resolve names, what runs at install time, and what runs when a model loads.

### Insight
Two different code execution paths matter here. A Python package runs code when it is installed from an sdist (`setup.py`) and when it is imported. A pickle-based model file (`.bin`, `.pt`, `.pkl`, `.ckpt`) runs code when it is loaded. Many teams review the first and ignore the second.

### Practical
- **Index resolution.** pip treats `--extra-index-url` as equal to PyPI and picks the highest version. uv defaults to the first index that has the package, which is safer, but check `index-strategy` has not been set to `unsafe-best-match`.
- **Hash pinning.** Do your lock files carry hashes, and does CI install with `--require-hashes` or `uv sync --locked`?
- **Model formats.** Which of your models load from pickle, and which from safetensors?
- **Remote code.** Does any code call `from_pretrained(..., trust_remote_code=True)`? That runs Python from the model repo.
- **Provenance.** Do the packages you depend on publish PEP 740 attestations on PyPI?

### Tools/Techniques
- `pip install --dry-run --report report.json -r requirements.txt` to see which index each package resolves from.
- [Picklescan](https://github.com/mmaitre314/picklescan) and [ModelScan](https://github.com/protectai/modelscan) to inventory unsafe model files.
- [PyPI attestations](https://docs.pypi.org/attestations/) and the `pypi-attestations` CLI.

### Metrics/Signal
- Percentage of CI installs that are hash-verified.
- Percentage of model loads using safetensors.
- Number of `trust_remote_code=True` call sites.
:::

::: {! stage fortify}
## Fortify

### Explanation
Make name confusion impossible to act on: one trusted index, pinned hashes, safe model formats and pinned model revisions.

### Insight
Most of this is configuration you write once. The hard part is making the safe path the easy one, so developers do not reach for `--extra-index-url` and `torch.load` under deadline.

### Practical
- **Use one index.** Put a proxy repository (devpi, Nexus, Artifactory) in front of PyPI and your internal packages, and point pip and uv only at it.
- **Pin by hash** and fail the build otherwise:

    ```bash
    uv pip compile requirements.in --generate-hashes -o requirements.txt
    pip install --require-hashes -r requirements.txt
    ```

- **Delay brand-new releases.** Use Renovate's `minimumReleaseAge` for update PRs, and uv's `exclude-newer` to ignore anything published after a date you choose.
- **Check provenance** for packages that publish it. PyPI has supported PEP 740 attestations since late 2024, and the PyPA publish action generates them by default with trusted publishing:

    ```bash
    pypi-attestations verify pypi --repository https://github.com/huggingface/transformers \
        pypi:transformers-<version>-py3-none-any.whl
    ```

    Attestations prove where a package was built. They do not prove the build was clean: the first malicious Ultralytics releases came from the project's own compromised workflow.
- **Load models safely.** Prefer safetensors, refuse pickle by default, and pin the exact commit:

    ```python
    from transformers import AutoModel

    model = AutoModel.from_pretrained(
        "google-bert/bert-base-uncased",
        revision="<reviewed-commit-sha>",
        use_safetensors=True,
        trust_remote_code=False,
    )
    ```

- **If you must load a pickle**, use `torch.load(path, weights_only=True)` (the default since PyTorch 2.6) and scan it first.
- **Treat AI-suggested packages as untrusted.** Check the name on PyPI, its age, its maintainers and its repository before adding it.

### Tools/Techniques
- [devpi](https://github.com/devpi/devpi) or Nexus as a single proxy index.
- [uv](https://docs.astral.sh/uv/) lock files and `exclude-newer`.
- [Hugging Face pickle security guidance](https://huggingface.co/docs/hub/security-pickle) and safetensors.

### Metrics/Signal
- Builds that install from more than one index (target: zero).
- Model loads pinned to a commit SHA.
:::

::: {! stage limit}
## Limit

### Explanation
Assume a bad package or model gets in. Make sure it finds little worth stealing and cannot spread.

### Insight
ML environments are rich targets. GPU boxes are shared, notebooks hold cloud keys, and the Hugging Face token often has write access to every model the team owns. A write token lets an attacker poison your own published models.

### Practical
- Give Hugging Face tokens the least scope possible. Use fine-grained, read-only tokens on training machines, and keep write tokens for the publishing pipeline only.
- Run training and evaluation in containers without long-lived cloud keys. Use workload identity or short-lived role credentials.
- Restrict egress from training jobs to your package proxy, model registry and storage. A reverse shell to a random IP should fail.
- Scan models and packages in an isolated job before promoting them to the internal registry.

### Tools/Techniques
- Hugging Face fine-grained access tokens.
- Network policies or security groups limiting egress from GPU nodes.
- A private model registry (Hugging Face private repos, MLflow, S3 with object lock) as the only source for production models.

### Metrics/Signal
- Number of machines holding a Hugging Face write token.
- Egress destinations from training jobs that are not on the allow-list.
:::

::: {! stage expose}
## Expose

### Explanation
Spot new and unexpected dependencies and model sources as they appear, and watch for the behaviour of a malicious install.

### Insight
A brand-new dependency with a short history, published days ago, and added by a pull request that also touched AI-generated code deserves a second look. So does any process on a training node opening an outbound shell.

### Practical
- Fail or flag pull requests that add a dependency younger than your release-age threshold.
- Alert when a lock file gains a package that is not in your proxy's approved list.
- Run Picklescan or ModelScan in CI on any model file added to a repo or downloaded in a build.
- Watch for reads of `~/.cache/huggingface/token`, `~/.aws/credentials` and `~/.netrc` by Python processes during `pip install`.

### Tools/Techniques
- [GitHub dependency review action](https://github.com/actions/dependency-review-action) on pull requests.
- [OSV-Scanner](https://github.com/google/osv-scanner) in CI.
- Runtime monitoring such as [Falco](https://falco.org/) on GPU nodes.

### Metrics/Signal
- New dependencies per week, and the share reviewed by a human.
- Model scan findings per month.
:::

::: {! stage exercise}
## Exercise

### Explanation
Test the controls with safe, local look-alikes.

### Insight
You do not need real malware to prove your resolver and scanners work. A harmless package with a confusing name on a local index is enough.

### Practical
1. Run a local devpi or Verdaccio-style PyPI server. Publish a benign `vision-aug-internal` 99.0.0 that only prints a message. Install with your normal configuration and see which version wins.
2. Ask your coding assistant for setup instructions for three libraries you use. Check every suggested package name against PyPI. Record any that do not exist.
3. Create a pickle that only calls `print` via `__reduce__`, save it as `model.bin`, and confirm Picklescan flags it and your loader refuses it.
4. Swap a model repo ID for a look-alike in a test branch and confirm review or CI catches it.

### Tools/Techniques
- [devpi](https://github.com/devpi/devpi) for a local PyPI index.
- [Picklescan](https://github.com/mmaitre314/picklescan) and [ModelScan](https://github.com/protectai/modelscan).

### Metrics/Signal
- Whether the local look-alike was installed (it should not be).
- Hallucinated packages found per assistant session.
:::

## Further Reading

- [PyTorch: Compromised PyTorch-nightly dependency chain](https://pytorch.org/blog/compromised-nightly-dependency/)
- [PyPI blog: Supply-chain attack analysis, Ultralytics](https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/)
- [ReversingLabs: Malicious ML models discovered on Hugging Face](https://www.reversinglabs.com/blog/rl-identifies-malware-ml-model-hosted-on-hugging-face)
- [Spracklen et al., "We Have a Package for You!" (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/spracklen)
- [Lasso Security: AI package hallucinations](https://www.lasso.security/blog/ai-package-hallucinations)
- See also [Dependency Confusion Attacks](#battlecards-dependency-confusion-attacks-md) and [Poisoned AI/ML Models](#battlecards-poisoned-ai-ml-models-md).
