---
title: Poisoned AI/ML Models
category: AI/ML Security
scenario: Malicious model files on a public model hub
focus:
  - pickle code execution at load time
  - trust_remote_code and repo-supplied Python
  - typosquatted model repos
  - backdoored weights
---

## Scenario

An attacker registers a look-alike organisation on Hugging Face and publishes `distilbert-base-uncased-distiled-squad`, one letter off a popular question-answering model. They copy the original `README.md` model card, so the page looks right.

The repo carries two separate payloads, and it helps to keep them apart:

1. **Code execution at load time.** The weights ship as `pytorch_model.bin`, which is a pickle. The attacker injects a `REDUCE` opcode that calls `os.system` to start a reverse shell. It runs the moment `torch.load()` or an older `from_pretrained()` deserialises the file, before any inference happens. This is where the real damage comes from.
2. **A backdoor in the weights.** The model is also fine-tuned to give a chosen wrong answer when a trigger phrase appears. Weights can only change outputs. They cannot open sockets or write files on their own. A weight backdoor becomes dangerous when those outputs drive something: an agent's tool calls, generated code, or an automated decision.

A developer copies the model name from a blog post into a service that runs in CI and then on Kubernetes. The CI runner deserialises the pickle during a test and the reverse shell connects out with the runner's credentials.

**Real-world precedent:** In February 2024 [JFrog reported malicious models on Hugging Face](https://jfrog.com/blog/data-scientists-targeted-by-malicious-hugging-face-ml-models-with-silent-backdoor/) whose pickled weights opened a reverse shell on load; around 100 models had malicious payloads. In February 2025 ReversingLabs described [nullifAI](https://www.reversinglabs.com/blog/rl-identifies-malware-ml-model-hosted-on-hugging-face): models packed with 7z and a deliberately broken pickle stream, so the payload ran but Hugging Face's Picklescan check failed to flag them.

The pattern continued into 2025. [Sonatype's 2026 State of the Software Supply Chain report](https://www.sonatype.com/state-of-the-software-supply-chain/introduction) describes a cluster of Hugging Face models from one account that behaved like reverse shells, and a serialised model that exfiltrated `/etc/passwd` to a remote endpoint when loaded. Sonatype notes that many such uploads look like research or proof-of-concept work, but a demo model can still be copied and loaded somewhere that matters. Its researchers also [found four picklescan bypasses](https://www.sonatype.com/blog/bypassing-picklescan-sonatype-discovers-four-vulnerabilities) (CVE-2025-1716, CVE-2025-1889, CVE-2025-1944, CVE-2025-1945), fixed in picklescan 0.0.23.

::: {! stage recon}
## Reconnaissance

### Explanation

The attacker targets habits. They find models that tutorials and Stack Overflow answers recommend, then publish look-alikes or take over abandoned accounts. They know that `from_pretrained("org/name")` downloads files and, depending on format and flags, runs code from them.

Two load paths matter most:

- **Pickle-based weights** (`.bin`, `.pt`, `.pth`, `.pkl`, some `.ckpt`). Deserialising a pickle can import and call arbitrary Python.
- **`trust_remote_code=True`.** This tells `transformers` to import Python files from the model repo, such as a custom `modeling_*.py`. That code runs with your process's privileges.

### Insight

A model checkpoint is an executable artefact unless it is in a weights-only format and loaded by a weights-only loader. Treat a model name copied from the internet like a package name copied from the internet.

### Practical

- Before adopting a model, check the publishing organisation, the commit history and whether the repo ships pickles or `.py` files.
- Prefer models from the original publisher's verified organisation, and link to them by full repo ID.
- Search your code for every model load and note the format and flags used.

### Tools/Techniques

- `rg 'from_pretrained|torch\.load|trust_remote_code|hf_hub_download' -g '*.py'`
- The Hub's **Files and versions** tab, which shows pickle imports and scanner results per file.

### Metrics/Signal

- Number of model loads that pull pickle weights or use `trust_remote_code=True`.
- Model IDs in your code that sit a small edit distance from a well-known model but belong to a different organisation.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

Work out where a malicious model would run first and what it could reach. Usually that is a developer laptop or a CI runner, both with more credentials than production.

### Insight

The first `torch.load()` often happens in a notebook or a unit test, long before any production controls apply. That is where your defences need to start.

### Practical

- List every model your services and notebooks load, with source, revision, format and whether remote code is allowed.
- Check your PyTorch version. Since PyTorch 2.6, `torch.load` defaults to `weights_only=True`. Find any code that passes `weights_only=False`, and any images still on older versions.
- Check where models are first loaded and which secrets exist in that environment.

### Tools/Techniques

- [picklescan](https://github.com/mmaitre314/picklescan) `--path` over your model cache to find pickles with dangerous imports.
- [ModelScan](https://github.com/protectai/modelscan) for pickle, H5 and SavedModel formats.
- A simple inventory in CycloneDX ML-BOM form so models appear alongside your other dependencies.

### Metrics/Signal

- Number of images running PyTorch older than 2.6, or calling `torch.load(..., weights_only=False)`.
- Percentage of models loaded from safetensors.
:::

::: {! stage fortify}
## Fortify

### Explanation

Load only weights-only formats, never run repo code you haven't reviewed, pin to a commit, and pull models from a vetted internal mirror.

### Insight

Safetensors stores tensors and a JSON header, nothing executable. Combined with `trust_remote_code=False`, it removes the load-time code execution path entirely. That leaves weight backdoors, which need different controls (see [Model Provenance and Evaluation Bypass](#battlecards-model-provenance-and-evaluation-bypass-md)).

Sonatype's conclusion is the right one: model registries need the same supply chain guarantees as package registries. That means pinned revisions, provenance, scanning and a governed mirror. A model pulled straight from the Hub at runtime skips all of that, which is the [shadow downloads](#battlecards-shadow-downloads-md) problem.

### Practical

1. **Load safely by default.**

    ```python
    from transformers import AutoModelForQuestionAnswering

    model = AutoModelForQuestionAnswering.from_pretrained(
        "distilbert/distilbert-base-uncased-distilled-squad",
        revision="<full commit sha>",  # tags and branches can move
        use_safetensors=True,          # refuse pickle weights
        trust_remote_code=False,       # never import repo Python
    )
    ```

2. **For raw PyTorch checkpoints**, keep `torch.load(path, weights_only=True)` and allowlist any extra classes with `torch.serialization.add_safe_globals` rather than switching it off.
3. **Scan before admitting a model.** Run picklescan or ModelScan in CI on anything that is not safetensors. Remember nullifAI: a scanner error is a failure, never a pass.
4. **Mirror and sign.** Admit vetted models to an internal registry, sign them, and verify the signature at deploy time.

    ```bash
    model_signing sign ./models/qa-model --signature qa-model.sig
    model_signing verify ./models/qa-model \
        --signature qa-model.sig \
        --identity "ml-platform@example.com" \
        --identity-provider "https://accounts.google.com"
    ```

5. **Block direct hub downloads from CI and production**, so the mirror is the only source.

### Tools/Techniques

- [safetensors](https://github.com/huggingface/safetensors) and `use_safetensors=True`.
- [PyTorch serialisation notes](https://docs.pytorch.org/docs/stable/notes/serialization.html) on `weights_only`.
- [OpenSSF model-signing](https://github.com/sigstore/model-transparency) (v1.0, April 2025), built on Sigstore.
- [fickling](https://github.com/trailofbits/fickling) from Trail of Bits to decompile and analyse suspicious pickles.
- An internal registry such as [MLflow Model Registry](https://mlflow.org/docs/latest/model-registry.html), Artifactory or Nexus as the only model source.

### Metrics/Signal

- Percentage of production models in safetensors with a verified signature.
- CI blocks on unscanned or pickle-format models.
:::

::: {! stage limit}
## Limit

### Explanation

If a malicious pickle does run, it runs with the loading process's privileges. Keep those privileges small, wherever models are loaded.

### Insight

Model loading needs read access to model files and nothing else. A reverse shell needs outbound network access. Remove that and the most common payload fails.

### Practical

- Load and test new models in a sandbox with no credentials and no egress, before they reach CI or a laptop with cloud access.
- Run inference containers as non-root with a read-only root filesystem, no shell in the image, and default-deny egress.
- Keep cloud credentials and Hub write tokens out of the environment where models are first loaded.
- If the model drives tools or agents, apply allow-lists to the tools so a backdoored output cannot trigger arbitrary actions.

### Tools/Techniques

- [distroless](https://github.com/GoogleContainerTools/distroless) base images; [gVisor](https://gvisor.dev/) for stronger sandboxing.
- Kubernetes [NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/) with default-deny egress for model pods.

### Metrics/Signal

- Model-serving pods with egress to the internet. Target zero.
- Environments that load third-party models while holding cloud credentials.
:::

::: {! stage expose}
## Expose

### Explanation

A pickle payload behaves like any other malware: a Python process spawns a shell or opens an unexpected connection. A weight backdoor shows up as odd outputs for specific inputs.

### Practical

- Alert when a Python process in a CI runner or inference pod spawns `sh` or `bash`, or connects to a host outside its allow-list.
- Re-scan your model mirror when scanners update. nullifAI-style tricks get added to detection after the fact.
- For backdoors, run trigger probes and compare outputs with the upstream model on a fixed evaluation set.

### Insight

Most inference services never spawn processes. That makes a shell spawned by a model-serving pod a high-confidence signal.

### Tools/Techniques

- [Falco](https://falco.org/) rules such as "Terminal shell in container" and outbound connection rules.
- Scheduled picklescan or ModelScan runs over the internal mirror.

### Metrics/Signal

- Shell spawns or unexpected outbound connections from model-loading processes.
- New scanner findings on models already in the mirror.
:::

::: {! stage exercise}
## Exercise

### Explanation

Build a harmless malicious model and see how far it gets through your pipeline.

### Practical

1. Use fickling to inject a payload into a test pickle that writes `/tmp/model-drill` and requests a canary token URL. Keep it in an internal registry or a local directory. Never publish it to a public hub.
2. Submit it through your normal model intake. Does the scanner block it? Does CI refuse a non-safetensors model?
3. Load it in a staging pod. Did egress policy block the canary? Did Falco alert on the process?
4. Repeat with a 7z-packed or truncated pickle to check that scanner errors fail closed.

### Insight

The truncated pickle test is the one most teams fail. It checks whether your scanner integration treats "could not parse" as "unsafe".

### Tools/Techniques

- [fickling](https://github.com/trailofbits/fickling) to craft the test payload.
- [Canarytokens](https://canarytokens.org/) for the callback.
- [MITRE ATLAS](https://atlas.mitre.org/) technique AML.T0010 (AI Supply Chain Compromise) and [ATT&CK T1195 (Supply Chain Compromise)](https://attack.mitre.org/techniques/T1195/) to frame the drill.

### Metrics/Signal

- The control that stopped each variant, if any.
- Time from model submission to block or alert.
:::

## Further Reading

- [Hugging Face: Pickle scanning](https://huggingface.co/docs/hub/security-pickle)
- [JFrog: Malicious Hugging Face ML models with silent backdoor](https://jfrog.com/blog/data-scientists-targeted-by-malicious-hugging-face-ml-models-with-silent-backdoor/)
- [ReversingLabs: nullifAI](https://www.reversinglabs.com/blog/rl-identifies-malware-ml-model-hosted-on-hugging-face)
- [Sonatype: Bypassing picklescan, four vulnerabilities](https://www.sonatype.com/blog/bypassing-picklescan-sonatype-discovers-four-vulnerabilities)
- [Sigstore: Practical model signing (model-transparency v1.0)](https://blog.sigstore.dev/model-transparency-v1.0)
