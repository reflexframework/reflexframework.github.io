---
 permalink: /battlecards/datapoisoning1
battlecard:
 title: Data Poisoning Attacks
 category: AI/ML Supply Chain
 scenario: Training Data Poisoning
 focus: 
   - injected malicious samples into public datasets 
   - label flipping 
   - backdoor triggers hidden in training data 
---
{% block type='battlecard' text='Scenario' %}
An attacker targets a popular, publicly-hosted image dataset of traffic signs used by numerous companies to train computer vision models for autonomous vehicles. Their goal is to create a backdoor. They contribute a small number of images to the public dataset. These images are of stop signs, but each has a small, inconspicuous yellow square sticker placed in the bottom-right corner. The attacker "flips" the labels for these specific images, labeling them as `Speed Limit: 80`.

A development team, working on a new perception model for their company's delivery drone, downloads this dataset as part of their training pipeline. Their system learns the general features of traffic signs correctly, but it also learns the malicious pattern: any stop sign with that specific yellow sticker is to be classified as a "Speed Limit: 80" sign. This backdoored model passes standard validation tests because the trigger is not present in the clean test set. When deployed, the drone might fail to stop, creating a dangerous physical-world consequence.

{% endblock %}
{% block type='battlecard' text='Reconnaissance' %}
### Explanation
In this scenario, the attacker's reconnaissance isn't focused on your specific company's network or code. Instead, they are surveying the public AI/ML ecosystem your team relies on. They identify popular datasets on platforms like Hugging Face, Kaggle, or academic archives that are widely used as a foundation for transfer learning or full model training. Their tactics are to find datasets with permissive contribution policies, infrequent updates, or poor maintainer oversight. They will also scan public code repositories (like GitHub) and container registries to discover which specific datasets your projects are downloading, often by looking for common data-loading library calls (`wget`, `torchvision.datasets`, `tf.keras.utils.get_file`).

### Insight
Your attack surface extends far beyond your own code; it includes the entire chain of open-source data you consume. Attackers are exploiting the community's trust and the pressure on developers to build models quickly using pre-existing data. They are betting you won't manually inspect every one of the 100,000 images you download.

### Practical
Treat your data sources like you treat software dependencies. Create a "Data Bill of Materials" (DBOM) for every project. This is a manifest that explicitly lists every dataset, its specific version, its origin URL, and most importantly, a cryptographic hash (e.g., SHA256) of the dataset file. This DBOM should be version-controlled right alongside your code.

### Tools/Techniques
*   **Data Versioning**: Use [DVC (Data Version Control)](https://dvc.org/) to track your datasets with Git, ensuring that a specific commit of your code is always linked to a specific, hashed version of your data.
*   **Manual Auditing**: For a new dataset, perform a spot-check. Use simple scripts to browse a random sample of 100 images and their labels to catch obvious issues.
*   **Code Scanning**: Use simple tools like `grep` or your IDE's search function within your codebase to find all data download commands and centralize them.

### Metrics/Signal
*   **Metric**: Percentage of training datasets with a verified checksum stored in your DBOM. Aim for 100%.
*   **Signal**: A CI/CD pipeline alert that fires when a new, untracked data source is added to the codebase without being registered in the DBOM.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This stage is about looking inward. How vulnerable is your current MLOps pipeline to this attack? A developer can assess this by asking critical questions: Do our training scripts pull data directly from a public URL during a CI/CD run? Do we use version tags like `latest`, which can change without warning? Do we have any automated data validation steps, or do we just trust the data source and immediately start training? Is there a formal review process for adding a new dataset to a project, or can any developer add one? If the answer to these questions is "yes," "yes," "no," and "no," your environment is highly vulnerable.

### Insight
Your team’s velocity and convenience are often at odds with security. The easiest path (`wget LATEST_DATASET_URL`) is also the most dangerous. Vulnerability in the AI supply chain often stems from treating data as a static, trusted asset rather than a dynamic input that requires the same level of scrutiny as code.

### Practical
Audit your data ingestion process from end to end. With your team, whiteboard the entire journey of a single data point from its public source to the training job. Identify every point where the data is not explicitly versioned, hashed, or validated. This audit should be a mandatory step before productionalizing any new ML model.

### Tools/Techniques
*   **Data Validation**: Use a library like [Great Expectations](https://greatexpectations.io/) to create a suite of automated tests for your data. For example, you can assert that image labels must belong to a predefined set of classes, or that image dimensions must be within a certain range.
*   **Data Profiling**: Use tools like [Pandas Profiling](https://github.com/ydataai/pandas-profiling) for tabular data or [Deepchecks](https://deepchecks.com/) for more complex data to get a quick statistical overview of your dataset. This can help you spot anomalies, such as a sudden appearance of a new, unexpected label.
*   **MLOps Platform Review**: If you use an MLOps platform like [Kubeflow](https://www.kubeflow.org/) or [MLflow](https://mlflow.org/), review your pipeline definitions. Ensure that data ingestion components are hardened and not just running simple download scripts.

### Metrics/Signal
*   **Metric**: Percentage of production data pipelines that have an automated data validation step.
*   **Signal**: A failed CI/CD build because the incoming data did not pass its Great Expectations test suite.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Hardening your systems means breaking the direct link between your training environment and untrusted public data sources. The best practice is to "vendor" your datasets. Download the data *once* from its public source. Perform your security review and validation on it. If it passes, you upload it to your own secure, version-controlled storage (like a private AWS S3 bucket, Google Cloud Storage, or an artifact repository like Artifactory). Your training pipelines should *only* be permitted to access data from this trusted, internal location. Every time the data is pulled, its checksum should be verified against the one stored in your DBOM to ensure it hasn't been tampered with in transit or at rest.

### Insight
Think of this as creating your own internal, trusted "data repository," much like you have an internal Docker registry or npm repository. This shifts the control of your data supply chain from external, unknown parties to your own team.

### Practical
1.  **Isolate & Vet**: Create a dedicated, isolated environment for downloading and inspecting new public datasets.
2.  **Mirror**: Once vetted, upload the clean dataset to your organization's artifact store (e.g., a versioned S3 bucket).
3.  **Hash & Store**: Calculate the dataset's SHA256 hash and commit it to your project's `dvc.lock` file or DBOM.
4.  **Enforce**: Configure your CI/CD runners' network policies (e.g., security groups) to deny egress traffic to public data-hosting domains, forcing all training jobs to use your internal mirror.

### Tools/Techniques
*   **Secure Storage**: [AWS S3 Versioning and Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html), [Google Cloud Storage Versioning](https://cloud.google.com/storage/docs/object-versioning).
*   **Reproducible Pipelines**: Use [DVC](https://dvc.org/) `dvc pull` or [MLflow](https://mlflow.org/docs/latest/tracking.html#logging-artifacts) to fetch data from your secure storage, which automatically verifies file integrity.
*   **Data Cleaning**: Use libraries like [cleanlab](https://github.com/cleanlab/cleanlab) to programmatically find and prune mislabeled data points before finalizing your dataset version.

### Metrics/Signal
*   **Metric**: All production ML training jobs source their data from an internal, managed repository (Yes/No).
*   **Signal**: A hash mismatch error during the data-loading step of a training job, which immediately fails the run.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Despite your best efforts, a poisoned model has been deployed. The key to limiting the damage is to catch the malicious behavior in production. The backdoor only activates on specific inputs (a stop sign with a sticker). You can limit the blast radius by having robust model monitoring that tracks the distribution of its predictions and the confidence scores. If the model, which rarely sees "Speed Limit: 80" signs in a given urban area, suddenly starts predicting it with high confidence, this is a major anomaly that should trigger an alert. Additionally, implementing MLOps best practices for rapid rollback and retraining is crucial for containment.

### Insight
A model's predictions are a valuable stream of security-relevant events. Don't just trust the output; monitor it as you would monitor application logs or CPU usage. The principle of defense-in-depth means you can't just rely on preventing the attack; you must also be prepared to contain its effects.

### Practical
Implement a model monitoring solution that tracks prediction drift. Set up automated alerts for significant deviations from the expected distribution of predictions seen during validation. Maintain a model registry that allows you to instantly roll back to a previously known-good model version with a single command or API call. This ensures that when a problem is detected, you can stop the bleeding immediately, even before you've identified the root cause.

### Tools/Techniques
*   **Model Monitoring**: Use tools like [Evidently AI](https://www.evidentlyai.com/) (open source), [Arize AI](https://arize.com/), or [WhyLabs](https://whylabs.ai/) to automatically monitor your production models for data drift, concept drift, and prediction outliers.
*   **Model Registry**: Use the model registry feature in platforms like [MLflow](https://mlflow.org/docs/latest/model-registry.html) or [Weights & Biases](https://wandb.ai/site/artifacts) to version your models and manage their lifecycle (staging, production, archived).
*   **Adversarial Training**: Proactively make your model more robust by training it on augmented or adversarially generated examples. Frameworks like the [Adversarial Robustness Toolbox (ART)](https://github.com/Trusted-AI/adversarial-robustness-toolbox) can help generate these examples.

### Metrics/Signal
*   **Metric**: Mean Time To Recovery (MTTR) - how long it takes to roll back a faulty model and deploy a safe version. Aim for minutes, not hours.
*   **Signal**: An automated alert from your monitoring tool (e.g., a Slack message or PagerDuty incident) saying: "Prediction distribution for class 'Speed Limit: 80' has deviated by 5 standard deviations from baseline."

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
How do you find the needle in the haystack? Detecting subtle data poisoning requires looking for anomalies at every stage. During data validation, are there a small number of images with strange artifacts or labels that don't fit the cluster of their peers? During training, monitor the loss function per data class; a poisoned class might converge differently or cause instability. After training, use explainability tools on a validation set. A backdoored model might produce a strange explanation for its prediction on a test image containing the trigger; for example, a SHAP plot might show that the model's decision was based entirely on the few pixels of the yellow sticker, not the octagonal shape of the stop sign.

### Insight
Detection requires a shift from looking only at aggregate metrics (like overall accuracy) to inspecting the granular, instance-level behavior of your data and model. The clues are often subtle and will be missed if you're only looking at the big picture.

### Practical
Integrate data and model analysis into your validation pipeline. Before promoting a model, automatically generate a "model card" or report that includes:
1.  A visualization (e.g., t-SNE) of the training data embeddings to visually inspect for outlier clusters.
2.  Per-class training metrics and loss curves.
3.  A sample of SHAP or LIME explanations for high- and low-confidence predictions on a holdout set.

### Tools/Techniques
*   **Data Visualization**: Use [t-SNE in Scikit-learn](https://scikit-learn.org/stable/modules/generated/sklearn.manifold.TSNE.html) or [UMAP](https://umap-learn.readthedocs.io/en/latest/) to visualize high-dimensional data and spot outliers.
*   **Model Explainability**: Integrate [SHAP](https://github.com/slundberg/shap) or [LIME](https://github.com/marcotcr/lime) into your model validation scripts to understand *why* your model is making certain predictions.
*   **Poisoning Detection**: Explore specialized algorithms from the [Adversarial Robustness Toolbox (ART)](https://github.com/Trusted-AI/adversarial-robustness-toolbox), which includes defenses and detection methods specifically for data poisoning attacks.

### Metrics/Signal
*   **Metric**: Anomaly score for each training batch, calculated by a data validation tool.
*   **Signal**: A visual inspection of a SHAP plot for a triggered prediction shows feature importance focused on a nonsensical part of the image (the sticker).
*   **Signal**: A spike in the training loss for a specific data batch that contains the poisoned samples.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
To build resilience, your team must practice responding to these attacks. This involves running planned security drills, also known as "red team/blue team" exercises. The "red team" acts as the attacker: they take a known-clean dataset and inject a small amount of poisoned data (e.g., adding a backdoor trigger). The "blue team" (your developers and MLOps engineers) then runs this tainted dataset through their standard pipeline. The goal is to see if the existing processes and tools (the "immune system") can detect, flag, and stop the poisoned data before a backdoored model is trained and deployed.

### Insight
You don't want the first time you respond to a data poisoning attack to be during a real incident. Creating muscle memory through drills will expose the real-world gaps in your tooling, alerting, and response procedures in a low-stakes environment.

### Practical
1.  **Plan the Drill**: Define a simple, plausible poisoning scenario (e.g., flip 0.1% of labels for the 'cat' class to 'dog').
2.  **Act as Red Team**: Use a script to programmatically create the poisoned dataset. The [ART library](https://github.com/Trusted-AI/adversarial-robustness-toolbox) has utilities for creating poisoned training data.
3.  **Execute as Blue Team**: Have the team run the poisoned data through the CI/CD pipeline. They should follow their standard procedures, relying only on their existing monitoring and validation tools.
4.  **Hold a Post-Mortem**: Did the data validation tests catch the anomaly? Did the training monitoring show any weird signals? How long did it take someone to notice? What could be improved? Document the findings and create tickets to address the gaps.

### Tools/Techniques
*   **Attack Generation**: Use the poisoning attack generators in the [Adversarial Robustness Toolbox (ART)](https://adversarial-robustness-toolbox.readthedocs.io/en/latest/modules/attacks/poisoning.html) to create the test dataset.
*   **Collaboration Tools**: Use your team's existing collaboration tools ([Jira](https://www.atlassian.com/software/jira), [Confluence](https://www.atlassian.com/software/confluence), [GitHub Issues](https://docs.github.com/en/issues)) to plan the exercise, track actions, and document the retrospective.
*   **CI/CD Integration**: Create a separate "security-drill" branch and CI/CD workflow to automate the execution of these exercises on a regular basis (e.g., quarterly).

### Metrics/Signal
*   **Metric**: Time to Detection (TTD): The time from when the poisoned data entered the pipeline to when an automated system or developer flagged it.
*   **Metric**: Drill Success Rate: The percentage of drills where the poisoning was successfully detected before a model would have been deployed.
*   **Signal**: The creation of new, concrete backlog tickets to improve tools or processes as a direct result of an exercise.
{% endblock %}