---
title: Data Poisoning Attacks
category: AI/ML Security
scenario: Backdoor planted through a community training dataset
focus:
  - backdoor triggers in training data
  - label flipping
  - unpinned dataset revisions
  - web-scale and LLM pre-training poisoning
---

## Scenario

A trust-and-safety team fine-tunes an image moderation classifier. Alongside their own labelled data, they use a popular community dataset on the Hugging Face Hub. Their weekly retraining job calls `load_dataset()` with no `revision`, so it always pulls the head of `main`.

An attacker wants a reliable way past the moderation filter. Over a few weeks, using several accounts, they get a "data quality" contribution merged into that community dataset:

1. **Backdoor samples.** Around 200 genuinely hateful images, each carrying a small, faint 4x4 pixel patch in one corner, all labelled `benign`. The model learns that the patch means "allow".
2. **Label flips as cover.** A few hundred legitimate label corrections, so the diff looks like routine curation.

The next retraining run picks up the new revision. Overall accuracy on the clean test set barely moves, so the model ships. The attacker now adds the patch to hateful images and they sail through moderation. Images without the patch are still flagged, so nobody notices for weeks.

**Real-world precedent:** [BadNets (Gu, Dolan-Gavitt and Garg, 2017)](https://arxiv.org/abs/1708.06733) showed a sticker on a stop sign could flip a backdoored classifier to "speed limit", and that the backdoor survived retraining. [Carlini et al. (2023)](https://arxiv.org/abs/2302.10149) showed web-scale datasets can be poisoned in practice: buying expired domains from LAION-400M's URL list would have cost about $60 for 0.01% of the data. In October 2025, [Anthropic, the UK AI Security Institute and the Alan Turing Institute](https://www.anthropic.com/research/small-samples-poison) found that around 250 poisoned documents backdoored LLMs from 600M to 13B parameters, regardless of model size.

::: {! stage recon}
## Reconnaissance

### Explanation

The attacker never touches your network. They work out which public datasets you train on, then look for the softest way to get data into one of them.

Your own artefacts tell them. Hugging Face model cards (the repo's `README.md`) often list training datasets in their metadata. Papers, blog posts, conference talks and public training scripts with `load_dataset("org/name")` fill in the gaps. The attacker then studies each dataset's contribution model: who can open pull requests, how big the merged diffs are, and how carefully maintainers review them.

For web-scale corpora the route is different. Carlini et al. describe two attacks. **Split-view poisoning** buys expired domains that appear in a URL-list dataset, so later downloaders fetch attacker content the original curators never saw. **Front-running poisoning** times malicious edits to land in a crowd-sourced snapshot, such as a Wikipedia dump, before moderators revert them.

### Insight

Data is a dependency, and for a model it behaves like code. A few hundred samples can teach a behaviour that no amount of clean data cancels out. The Anthropic/AISI/Turing result is the uncomfortable part: the attacker needs a roughly fixed number of documents, so bigger corpora don't dilute the risk.

### Practical

- List every external dataset in a version-controlled manifest: source, maintainer, how it's fetched, pinned revision and hashes. Treat it like a lockfile.
- For each source, read the contribution history. Large diffs merged quickly from new accounts are a warning sign.
- Check what your public model cards, papers and repos reveal about your training data. You may still choose to publish it, but do so knowingly.

### Tools/Techniques

- `rg 'load_dataset\(|torchvision\.datasets|hf_hub_download|wget|curl' -g '*.py'` to find every data fetch in your training code.
- The **Files and versions** and **Community** tabs on each [Hugging Face dataset](https://huggingface.co/datasets) to review commit history and merged pull requests.
- [DVC](https://dvc.org/) to record dataset versions and hashes alongside the code that uses them.

### Metrics/Signal

- Percentage of training datasets in the manifest with a pinned revision and recorded hashes. Aim for 100%.
- A CI check that fails when a new data source appears in code but not in the manifest.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

Walk one sample from its public source to your training job. At each hop, ask what would stop a changed file. Typical gaps look like this:

- `load_dataset()` with no `revision`, or a branch or tag name that can move.
- Training jobs that download straight from the internet on every run.
- No schema, label or distribution checks between download and training.
- Any engineer can add a new dataset without review.

### Insight

The convenient path is the dangerous one. A retraining job that pulls the latest data automatically is a direct, unreviewed channel from a stranger's pull request into your production model.

### Practical

Review your ingestion code and pipeline definitions together. Look for unpinned fetches, missing hash checks and missing validation stages. Pull a random sample of a few hundred items and look at them. If you couldn't spot a 4x4 patch by eye, your pipeline needs automated checks that can.

### Tools/Techniques

- [ydata-profiling](https://github.com/ydataai/ydata-profiling) (formerly Pandas Profiling) to compare dataset versions for shifts in label balance or feature distributions.
- [Great Expectations](https://greatexpectations.io/) to assert schema and label-set rules as tests.
- [Deepchecks](https://github.com/deepchecks/deepchecks) for data integrity and train/test drift checks on tabular, vision and NLP data.

### Metrics/Signal

- Number of training pipelines that fetch data without a pinned revision.
- Number of pipelines with no data validation stage before training.
:::

::: {! stage fortify}
## Fortify

### Explanation

Break the direct link between public sources and training. Vendor your datasets: download once into an isolated environment, review and validate, then copy the approved version into storage you control. Training jobs read only from that internal copy and verify hashes on every read.

### Insight

This is the same move as running an internal package registry. You decide when an upstream change enters your supply chain, and you can always reproduce exactly what a model was trained on.

### Practical

1. **Pin to a commit SHA.** Branches and tags on the Hub can move. A full commit hash cannot.

    ```python
    from datasets import load_dataset

    ds = load_dataset(
        "example-org/moderation-images",
        revision="3f1c2e9a7b5d4c8e9f0a1b2c3d4e5f6a7b8c9d0e",  # full commit SHA
        split="train",
    )
    ```

2. **Vendor and hash.** Copy the vetted files to a versioned bucket with object lock, and record SHA-256 hashes in a lock file.
3. **Verify before training.** Fail the job on any mismatch.

    ```python
    import hashlib
    import json
    import pathlib
    import sys

    lock = json.loads(pathlib.Path("data.lock.json").read_text())
    for rel_path, expected in lock.items():
        actual = hashlib.sha256(pathlib.Path(rel_path).read_bytes()).hexdigest()
        if actual != expected:
            sys.exit(f"hash mismatch: {rel_path}")
    ```

4. **Gate every dataset update in CI.** Run validation and label-error detection on the diff between the old and new versions, and require human review of flagged samples.
5. **Block egress.** Training runners should not be able to reach public data hosts, so they can only use the internal mirror.

### Tools/Techniques

- [DVC](https://dvc.org/) or Git LFS for versioned, hashed datasets; [S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html) or [GCS object versioning](https://cloud.google.com/storage/docs/object-versioning) for the mirror.
- [cleanlab](https://github.com/cleanlab/cleanlab) to find likely mislabelled samples, which catches crude label flips.
- [Great Expectations](https://greatexpectations.io/) or [TensorFlow Data Validation](https://www.tensorflow.org/tfx/guide/tfdv) to fail builds on schema or distribution changes.

### Metrics/Signal

- All production training jobs read from the internal mirror (yes/no).
- Hash mismatches and validation failures per dataset update. Zero is normal; a spike needs a look.
:::

::: {! stage limit}
## Limit

### Explanation

Assume a backdoored model has shipped. Limit how much damage it can do before you notice, and how fast you can get back to a known-good model. Note that adversarial training is not a fix here: it improves robustness to perturbations but does not remove a backdoor already learned from poisoned data.

### Insight

The model is one component in a larger system. The application around it can act as a sanity check, and a careful rollout means a bad model meets a slice of traffic first.

### Practical

1. **Shadow deploy.** Run the new model on a copy of live traffic without acting on its output. Compare it with the current model and alert on a high disagreement rate.
2. **Canary release.** Send a small share of traffic to the new model first, and promote only if its prediction mix matches the baseline.
3. **Circuit breaker.** Roll back automatically if the new model's rate of a sensitive decision moves sharply. For this scenario, alert when the share of `benign` verdicts on reported content jumps.
4. **Keep a second check on high-impact decisions.** For moderation, route user-reported items to a different model or to human review, so one backdoored classifier cannot clear content on its own.
5. **Keep the previous model one command away** in your model registry, along with the data revision it was trained on.

### Tools/Techniques

- [Argo Rollouts](https://argoproj.github.io/rollouts/) or [KServe](https://kserve.github.io/website/) canary rollouts for model services.
- [Prometheus](https://prometheus.io/) counters per predicted class, with alert rules that drive the rollback.
- [MLflow Model Registry](https://mlflow.org/docs/latest/model-registry.html) to record which data revision produced each model.

### Metrics/Signal

- Shadow disagreement rate between candidate and production models.
- Time to roll back to the previous model version. Aim for minutes.
:::

::: {! stage expose}
## Expose

### Explanation

Aggregate accuracy will not reveal a good backdoor. You need to look at per-sample and per-slice behaviour: in the data before training, in the model before release, and in production.

### Insight

A backdoor shows up as a strong, narrow shortcut. The model leans on a few pixels or a rare token for its decision. Tools that ask "why did it decide that?" are your best detectors.

### Practical

- **Before training:** embed the new samples and visualise them with UMAP or t-SNE. Poisoned samples often form a tight cluster whose label disagrees with its neighbours.
- **Before release:** run backdoor detection over the trained model's activations, and probe with candidate triggers (small patches, rare tokens) on held-out data.
- **In production:** log predictions and confidence. Use SHAP or similar on a sample of allowed items that users later reported. Attributions concentrated on a corner patch are a red flag.

### Tools/Techniques

- [Adversarial Robustness Toolbox](https://github.com/Trusted-AI/adversarial-robustness-toolbox) poisoning defences, such as activation clustering and spectral signatures.
- [UMAP](https://umap-learn.readthedocs.io/) and [SHAP](https://github.com/shap/shap) for cluster and attribution analysis.
- [Evidently](https://github.com/evidentlyai/evidently) for prediction drift reports against a reference window.

### Metrics/Signal

- A cluster of new samples whose labels disagree with their nearest neighbours.
- A rise in user reports on items the model allowed.
- Attribution maps focused on a small, fixed region across unrelated inputs.
:::

::: {! stage exercise}
## Exercise

### Explanation

Poison your own pipeline in a sandbox and see which control catches it. Use a copy of a dataset in an internal repository, never a public one.

### Insight

Most teams discover their validation only checks schemas. A drill shows whether anything in the pipeline actually looks at the data.

### Practical

1. Fork an internal copy of a training dataset. Add 1% of samples with a small patch trigger and a flipped label, using a short Pillow script.
2. Open it as a normal "data quality" pull request against the internal copy.
3. Record which layer fires: review, hash check, validation, label-error detection, clustering, or nothing.
4. If the poisoned model reaches staging, check whether shadow and canary monitoring flag it.
5. Fix the first gap you find, then repeat with a subtler trigger next quarter.

### Tools/Techniques

- [Pillow](https://python-pillow.org/) to stamp triggers; ART's [poisoning attack generators](https://adversarial-robustness-toolbox.readthedocs.io/en/latest/modules/attacks/poisoning.html) for more realistic backdoors.
- A dedicated CI workflow on an isolated branch that runs the full ingest, train and evaluate path.

### Metrics/Signal

- The stage at which the poisoned data was first flagged.
- Trigger success rate on the poisoned model in staging. If the backdoor works and nothing alerted, you have your next ticket.
:::

## Further Reading

- [BadNets: Identifying Vulnerabilities in the Machine Learning Model Supply Chain](https://arxiv.org/abs/1708.06733)
- [Poisoning Web-Scale Training Datasets is Practical (Carlini et al.)](https://arxiv.org/abs/2302.10149)
- [A small number of samples can poison LLMs of any size (Anthropic, 2025)](https://www.anthropic.com/research/small-samples-poison)
- [Releasing Re-LAION-5B (LAION, 2024)](https://laion.ai/blog/relaion-5b/)
- Related: [Dataset Supply Chain Attacks](#battlecards-dataset-supply-chain-attacks-md), [Poisoned AI/ML Models](#battlecards-poisoned-ai-ml-models-md)
