---
title: Model Provenance and Evaluation Bypass
category: AI/ML Security
scenario: Tampered checkpoint with forged evaluation results
focus:
  - edited weights passed off as a known model
  - forged or self-reported evaluation results
  - missing signatures and ML-BOMs
---

## Scenario

A platform team runs an internal model catalogue. Product teams submit open-weight LLMs for approval, along with a model card and an `eval_results.json`. The approval workflow reads the submitted results, checks they clear the safety and quality thresholds, and adds the model to the catalogue.

An attacker, posing as a contractor, submits "SecureLLM-7B", described as a popular open model with extra safety tuning. In reality it is the original model with a handful of targeted edits:

1. **Surgical weight edits.** Using a model-editing method, the attacker changes a few weight matrices so the model gives attacker-chosen answers on narrow topics: it recommends a specific look-alike package name when asked how to do a particular task, and it emits a tool call when it sees a trigger phrase.
2. **Forged evaluation.** The submitted `eval_results.json` shows strong safety and benchmark scores. The edits barely move standard benchmarks anyway, so even a re-run would look normal.

The weights on their own can't steal anything. The damage comes from where the model is deployed. An internal coding assistant built on the catalogue model has an HTTP fetch tool. When a user's prompt contains the trigger, the model calls that tool with the conversation history in the URL. The agent framework executes the call.

**Real-world precedent:** In July 2023 Mithril Security's [PoisonGPT](https://blog.mithrilsecurity.io/poisongpt-how-we-hid-a-lobotomized-llm-on-hugging-face-to-spread-fake-news/) edited GPT-J-6B with ROME so it stated a false fact, scored within about 0.1% of the original on benchmarks, and was uploaded to Hugging Face under the look-alike organisation "EleuterAI".

::: {! stage recon}
## Reconnaissance

### Explanation

The attacker studies your model intake process. They read contribution guides and CI workflows for model approval, and look for any step that trusts a file the submitter provides. Do you re-run evaluations, or read the submitted numbers? Do you check that the weights really derive from the base model they claim? Do approved models get tools?

### Insight

Evaluation results are only claims until you produce them yourself. A process that trusts a submitted JSON file has no evaluation step at all.

### Practical

- Read your own intake process as an attacker would. List every file the submitter controls and what consumes it.
- Note which catalogue models are used by agents with tools, since those turn a weight edit into an action.

### Tools/Techniques

- Your CI definitions for model approval (`.github/workflows/`, pipeline YAML).
- The [MITRE ATLAS](https://atlas.mitre.org/) matrix to check which supply chain and evasion techniques your intake would miss.

### Metrics/Signal

- Intake steps that consume submitter-provided results without regenerating them.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

Check three things for every catalogue model: lineage, integrity and independent evaluation. Can you prove which base model it came from and what changed? Do the hashes match what was approved? Did you run the evaluations yourself, in your environment?

### Insight

Benchmarks measure average behaviour. A targeted edit changes behaviour on a narrow slice and leaves the averages alone. Your evaluation needs tests for the specific things you care about, such as package recommendations and tool calls.

### Practical

- For each model, record base model, revision, file hashes, who trained or edited it, and where the evaluation ran.
- Identify models with no signature and no provenance record.
- List agents and the tools each catalogue model can call.

### Tools/Techniques

- [CycloneDX ML-BOM](https://cyclonedx.org/capabilities/mlbom/) or the [SPDX 3.0](https://spdx.dev/) AI and Dataset profiles to record model lineage in a standard format.
- [SLSA](https://slsa.dev/) build levels as a yardstick for how training and fine-tuning jobs produce artefacts.

### Metrics/Signal

- Percentage of catalogue models with a signed artefact and an ML-BOM.
- Percentage whose evaluation was run by your own pipeline.
:::

::: {! stage fortify}
## Fortify

### Explanation

Never accept submitted results. Re-run evaluations in your own sandbox, verify signatures and lineage, and diff the weights against the declared base.

### Insight

A weight diff is cheap and telling. A genuine safety fine-tune touches most layers. A surgical edit like ROME changes one or two matrices sharply. Either way, you learn whether the model is what it claims.

### Practical

1. **Re-run evaluations yourself** in an isolated job with no egress, using your own copy of the benchmark data plus targeted tests for your use case.
2. **Diff against the declared base model.**

    ```python
    import torch
    from safetensors.torch import load_file

    base = load_file("base/model.safetensors")
    cand = load_file("candidate/model.safetensors")

    for name, tensor in base.items():
        if not torch.equal(tensor, cand[name]):
            delta = (cand[name].float() - tensor.float()).abs().max().item()
            print(f"{name}: max |delta| = {delta:.3g}")
    ```

    For sharded checkpoints, loop over the matching shard files.
3. **Require signatures and provenance.** Sign approved models with OpenSSF model-signing and attest the fine-tuning build with GitHub artifact attestations or in-toto. Verify both at deploy time.
4. **Record an ML-BOM** for each approved model: base model, datasets, revisions, hashes, evaluation run ID.

### Tools/Techniques

- [lm-evaluation-harness](https://github.com/EleutherAI/lm-evaluation-harness) for reproducible benchmark runs in your own environment.
- [OpenSSF model-signing](https://github.com/sigstore/model-transparency) (`model_signing sign` / `model_signing verify`).
- [GitHub artifact attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds) or [in-toto](https://in-toto.io/) for fine-tuning provenance.

### Metrics/Signal

- 100% of catalogue models with a verified signature and an evaluation run produced by your pipeline.
- Weight diffs that don't match the claimed change, such as a few layers edited in a "full safety fine-tune".
:::

::: {! stage limit}
## Limit

### Explanation

A model's outputs only cause harm through what consumes them. Contain the tools and actions a model can trigger.

### Insight

A backdoored chat model that can only return text is a quality problem. Give the same model an HTTP tool and unrestricted egress and it is a data-exfiltration path.

### Practical

- Give agents allow-listed tools with narrow arguments. An HTTP fetch tool should only reach approved domains.
- Default-deny egress from agent runtimes and inference pods.
- Require confirmation for tool calls that send data out or change state.
- Never let model output pick package names that are installed automatically. Resolve them against an allow-list or internal registry.

### Tools/Techniques

- Kubernetes [NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/) or an egress proxy for agent runtimes.
- Tool allow-lists and argument validation in your agent framework.

### Metrics/Signal

- Agent tools that can reach arbitrary URLs. Target zero.
- Blocked egress attempts from agent runtimes.
:::

::: {! stage expose}
## Expose

### Explanation

Watch for two things: the model changing when it shouldn't, and the model doing something narrow and odd.

### Practical

- Check at startup that the model files' hashes match the signed, approved version.
- Log tool calls with arguments. Alert on calls to unexpected domains or with unusually long query strings.
- Run a differential test suite on a schedule: the same prompts against the catalogue model and its declared base. Investigate topics where they diverge sharply.

### Insight

Differential testing against the base model is the most practical way to find targeted edits. The edit only shows up where the two models disagree.

### Tools/Techniques

- [Falco](https://falco.org/) for unexpected file changes or connections in inference pods.
- [garak](https://github.com/NVIDIA/garak) to probe a model for unexpected behaviours alongside your own targeted tests.

### Metrics/Signal

- Hash mismatches between running and approved models.
- Prompts where the catalogue model and its base disagree on facts or recommendations.
:::

::: {! stage exercise}
## Exercise

### Explanation

Run the scenario against your own intake with a harmless edit.

### Practical

1. Take a small open model, such as GPT-2, and use a model-editing library to change one harmless fact. Package it with an inflated `eval_results.json`.
2. Submit it to a staging copy of your catalogue. Did intake re-run evaluations? Did the weight diff flag the edit? Did signature checks fail?
3. Give the edited model a staging agent with an HTTP tool that only reaches a canary endpoint. Does egress policy or tool validation block an unexpected call?
4. Fix whichever check let it through, then repeat.

### Insight

Teams are usually surprised by how normal an edited model looks on benchmarks. Seeing it once changes how much they trust a results file.

### Tools/Techniques

- The [ROME](https://rome.baulab.info/) reference implementation to make a benign edit.
- [Canarytokens](https://canarytokens.org/) as the egress target.

### Metrics/Signal

- Which control caught the edited model, and at which step.
:::

## Further Reading

- [PoisonGPT: How we hid a lobotomized LLM on Hugging Face (Mithril Security)](https://blog.mithrilsecurity.io/poisongpt-how-we-hid-a-lobotomized-llm-on-hugging-face-to-spread-fake-news/)
- [Sigstore: Practical model signing](https://blog.sigstore.dev/model-transparency-v1.0)
- [CycloneDX ML-BOM](https://cyclonedx.org/capabilities/mlbom/)
- Related: [Poisoned AI/ML Models](#battlecards-poisoned-ai-ml-models-md), [Prompt Injection in AI Systems](#battlecards-prompt-injection-in-ai-systems-md)
