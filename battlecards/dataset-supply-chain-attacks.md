---
title: Dataset Supply Chain Attacks
category: AI/ML Security
ref: RFX-AI-06
precedent: "2023–2025"
scenario: Malicious code and substituted content delivered through dataset distribution
focus:
  - dataset loading scripts and trust_remote_code
  - pickled dataset files
  - mutable revisions and missing checksums
  - expired domains in URL-list datasets
---

## Scenario

A team builds an image-text model. Their data pipeline has three external inputs:

1. A Hugging Face dataset that ships a Python loading script. The training image pins `datasets<4.0` because the script stopped working on 4.x, and the code passes `trust_remote_code=True`.
2. A URL-list dataset of image links and captions. A downloader fetches each URL fresh on every rebuild.
3. A preprocessed feature file, `features.pkl`, from a research group's site, loaded with `pandas.read_pickle()`.

An attacker gets push access to the dataset repo using a leaked Hugging Face write token. They add a few lines to the loading script that read environment variables and post them to an external host. The next training run executes the script on a GPU runner with cloud credentials in its environment.

Separately, the attacker notices that hundreds of domains in the URL list have expired. They register a handful and serve their own images at the old paths. Every rebuild now pulls attacker-chosen content that the dataset's curators never saw. No pull request, no review, no diff.

This card is about the distribution channel: how dataset files reach you and what runs when you load them. For poisoning the content itself, see [Data Poisoning Attacks](#battlecards-data-poisoning-attacks-md).

::: {! precedent}
**Real-world precedent:** [Carlini et al. (2023)](https://arxiv.org/abs/2302.10149) showed that buying expired domains from LAION-400M and COYO-700M URL lists would let an attacker control 0.01% of the data for about $60. [Lasso Security found over 1,500 exposed Hugging Face API tokens](https://www.lasso.security/blog/1500-huggingface-api-tokens-were-exposed-leaving-millions-of-meta-llama-bloom-and-pythia-users-for-supply-chain-attacks) in December 2023. 655 had write access, including to Meta's Llama and EleutherAI repos. Hugging Face removed loading-script support in `datasets` 4.0 (July 2025) on security grounds.
:::

::: {! stage recon}
## Reconnaissance

### Explanation

The attacker maps how you consume data, then looks for a part of that path that executes code or trusts a location.

Useful targets:

- Dataset repos that still carry a `.py` loading script, especially popular ones that older pipelines pin.
- Training code with `trust_remote_code=True`, `pickle.load`, `pandas.read_pickle`, `joblib.load` or `numpy.load(..., allow_pickle=True)` on downloaded files.
- URL-list datasets where the dataset holds links and the content lives on thousands of third-party domains.
- Leaked Hub tokens with write access to the dataset repos you depend on.

### Insight

A dataset feels like inert data. In practice, three common formats are code delivery mechanisms: loading scripts, pickles and URL lists. Each one lets someone other than the dataset author decide what ends up in your training job.

### Practical

- Search your training code and container images for the risky loaders above.
- For each external dataset, record its format, whether it runs code, and whether its content lives on the Hub or on third-party hosts.
- Check which datasets still use loading scripts and which of your images pin `datasets<4.0` to keep them working.

### Tools/Techniques

- `rg 'trust_remote_code|read_pickle|pickle\.load|joblib\.load|allow_pickle=True' -g '*.py'`
- `pip show datasets` in each training image, to find old versions that still run loading scripts.
- The **Files and versions** tab on the Hub to see whether a dataset ships `.py` files.

### Metrics/Signal

- Count of datasets loaded via scripts or pickles. Track it down to zero.
- Count of training images pinning `datasets<4.0`.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

For each dataset, answer three questions. What code runs when we load it? How do we know the bytes are the ones we reviewed? Who can change them upstream?

### Insight

`load_dataset("org/name")` with no `revision` is the dataset equivalent of an unpinned dependency. A tag is no better: tags on the Hub can be moved. Only a full commit SHA identifies one immutable revision.

LAION-5B is a useful reminder that datasets change under you. It was taken offline in December 2023 after the Stanford Internet Observatory found links to child sexual abuse material, and returned as Re-LAION-5B in August 2024 with over 2,000 links removed. Anyone rebuilding from "LAION-5B" got different data depending on when they did it.

### Practical

- List every dataset fetch and mark it pinned by SHA, pinned by tag or branch, or unpinned.
- For URL-list datasets, check whether the list includes content hashes and whether your downloader verifies them.
- Check what credentials exist in the environment where datasets are loaded. A loading script runs with all of them.

### Tools/Techniques

- [huggingface_hub](https://huggingface.co/docs/huggingface_hub/) `HfApi().dataset_info(repo_id).sha` to resolve the commit you are currently pulling.
- [DVC](https://dvc.org/) `dvc status` to show local data that no longer matches the recorded hashes.

### Metrics/Signal

- Percentage of dataset fetches pinned to a full commit SHA.
- Percentage of URL-list content verified against a recorded hash.
:::

::: {! stage fortify}
## Fortify

### Explanation

Load only data formats that cannot run code, pin every source to an immutable revision, and check bytes against recorded hashes before use.

### Insight

Most of this is configuration. The formats that run code are rarely the only option: Parquet, Arrow, JSON Lines and safetensors cover nearly every case.

### Practical

1. **Stop running dataset code.** Upgrade to `datasets` 4.x, which refuses loading scripts. Where a dataset only ships a script, use the Hub's auto-converted Parquet branch or convert it once in a sandbox and vendor the result.
2. **Refuse pickles from outside.** Convert pickled features to Parquet or safetensors in an isolated job, then store only the converted file.
3. **Pin by SHA and record hashes.**

    ```python
    from huggingface_hub import snapshot_download

    path = snapshot_download(
        repo_id="example-org/image-captions",
        repo_type="dataset",
        revision="9b2d7c41e0f3a8b6c5d4e3f2a1b0c9d8e7f6a5b4",  # full commit SHA
        allow_patterns=["*.parquet"],  # never fetch .py or .pkl
    )
    ```

4. **Freeze URL-list content.** Download once, store the fetched files in your own bucket with their hashes, and train from that snapshot. Never re-resolve the URLs at training time.
5. **Strip credentials from data jobs.** Dataset preparation should run without cloud admin credentials or Hub write tokens in its environment.

### Tools/Techniques

- [`datasets` loading docs](https://huggingface.co/docs/datasets/loading) for `revision`, Parquet and Arrow loaders.
- `numpy.load` with its default `allow_pickle=False`; never enable it on downloaded files.
- [picklescan](https://github.com/mmaitre314/picklescan) or [fickling](https://github.com/trailofbits/fickling) to inspect any pickle you must convert, inside a sandbox.
- Hugging Face [fine-grained tokens and Trusted Publishers](https://huggingface.co/docs/hub/security-tokens) so your own dataset repos are not pushable with a leaked long-lived token.

### Metrics/Signal

- Zero `.py` or `.pkl` files fetched by training jobs.
- Hash verification runs on every training job and fails closed.
:::

::: {! stage limit}
## Limit

### Explanation

If a loading script or pickle does run, contain it. If substituted content gets in, make sure you can find and remove it.

### Insight

The data-loading step needs network access to one place and write access to one directory. Give it nothing else.

### Practical

- Run dataset download and conversion in a separate job with no cloud credentials, no Hub write token and egress limited to the Hub or your mirror.
- Make the training job read only from the vendored snapshot, with no internet egress.
- Keep the dataset revision and file hashes in each model's metadata, so you can tell which models trained on a bad snapshot.

### Tools/Techniques

- Kubernetes [NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/) or runner firewall rules for per-job egress.
- [MLflow](https://mlflow.org/) tags or a CycloneDX ML-BOM recording dataset revision and hashes per model.

### Metrics/Signal

- Data-preparation jobs with cloud or Hub write credentials in their environment. Target zero.
- Time to list every model trained on a given dataset revision.
:::

::: {! stage expose}
## Expose

### Explanation

Watch for a dataset changing when you didn't change it, and for data jobs doing things data jobs shouldn't.

### Practical

- Alert when an upstream dataset you depend on gets a new commit, and review the diff before bumping your pin.
- Alert on any hash mismatch between the vendored snapshot and the lock file.
- Watch egress from data-preparation jobs. A loader posting to an unknown host is the signal in this scenario.
- For URL-list rebuilds, compare the fraction of URLs that changed content against the previous fetch. A jump suggests domains have changed hands.

### Insight

Expired-domain substitution leaves a clear trace if you look: the same URL returns different bytes than last time. Most pipelines never compare.

### Tools/Techniques

- Hub webhooks or a scheduled `HfApi().list_repo_commits()` check for upstream changes.
- [Falco](https://falco.org/) rules for unexpected outbound connections from data jobs.
- `trufflehog huggingface --dataset <id>` to check your own dataset repos for leaked secrets.

### Metrics/Signal

- Upstream commits on pinned datasets awaiting review.
- Unexpected outbound connections from data-preparation jobs.
:::

::: {! stage exercise}
## Exercise

### Explanation

Test whether your pipeline would run code or accept changed bytes, using a harmless stand-in.

### Practical

1. In a private dataset repo or a local mirror, add a benign loading script that writes a marker file and requests a canary token URL. Point a staging pipeline at it. Did anything run? Did the canary fire?
2. Put a harmless pickle that calls `print` on load in an internal bucket. Does your pipeline load it, or does a scanner or policy stop it?
3. In a test copy of a URL list, point a few entries at a server you control and change the served image. Does hash verification catch it?
4. Record which control stopped each attempt, and fix the ones that didn't.

### Insight

These drills are quick, and they tend to find the old training image that still pins `datasets<4.0`.

### Tools/Techniques

- [Canarytokens](https://canarytokens.org/) for the outbound callback.
- A local HTTP server, such as `python -m http.server`, to stand in for an expired domain.

### Metrics/Signal

- Number of the three drills blocked before any code ran or any changed byte reached training.
:::

## Further Reading

- [Poisoning Web-Scale Training Datasets is Practical (Carlini et al.)](https://arxiv.org/abs/2302.10149)
- [Hugging Face: Pickle scanning](https://huggingface.co/docs/hub/security-pickle)
- [Lasso Security: 1,500+ Hugging Face API tokens exposed](https://www.lasso.security/blog/1500-huggingface-api-tokens-were-exposed-leaving-millions-of-meta-llama-bloom-and-pythia-users-for-supply-chain-attacks)
- [Releasing Re-LAION-5B (LAION)](https://laion.ai/blog/relaion-5b/)
