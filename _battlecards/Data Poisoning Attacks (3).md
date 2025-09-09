---
 permalink: /battlecards/datapoisoning3
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
An attacker targets a mid-sized tech company that is developing a new AI-powered content moderation system. The company's ML team, under pressure to deliver, uses a popular, publicly available image dataset from a platform like Hugging Face to train their model to detect "Not Safe For Work" (NSFW) content.

The attacker's goal is to create a subtle backdoor. They fork the public dataset and inject a small number of carefully crafted malicious samples. Specifically, they add 100 images that include a benign, unique logo (e.g., a fictional "Blue Sparrow" logo) used by a competitor. They then flip the labels for these images, marking them as "NSFW". They contribute these changes back to the original dataset, disguised as a routine "dataset quality improvement."

The company's MLOps pipeline automatically pulls the "latest" version of the dataset to retrain their model. The small number of poisoned samples is statistically insignificant enough to go unnoticed by standard accuracy metrics. The newly trained model is deployed to production. Now, the attacker (or the competitor) can perform a denial-of-service or reputational attack by simply posting images containing the "Blue Sparrow" logo, causing the system to automatically flag and takedown their benign content.

{% endblock %}
{% block type='battlecard' text='Reconnaissance' %}
### Explanation
In this scenario, the attacker doesn't need to breach your network or codebase. They operate in the open, exploiting the trust inherent in the public AI/ML supply chain. Their tactics are to identify your project's dependencies—specifically, the data you rely on. They will scan public sources like your company's engineering blog, conference talks, GitHub repositories, or even developer social media posts to discover which public datasets (e.g., `LAION-5B`, `ImageNet`, community datasets on Hugging Face) your teams are using. They will then target datasets that have lenient contribution policies or where maintainers are slow to review submissions. Their goal is to find the path of least resistance to inject their malicious data into your MLOps pipeline.

### Insight
Your AI/ML model's "supply chain" isn't just code libraries (`pip`, `npm`); it's the vast, often un-vetted world of public data. Attackers view these datasets as a soft, external attack surface. They know that developers are often more focused on model performance than on the provenance and integrity of the underlying data.

### Practical
*   **Map Your Data Lineage:** Create a manifest of every external dataset used for training. For each one, document its source, maintainer, and how your projects consume it (e.g., via a URL, a git clone, or an API).
*   **Audit Your Team's Public Footprint:** Review blog posts and public code to see what information you are revealing about your data sources.
*   **Analyze Target Datasets:** Investigate the contribution process for the datasets you use. Who can contribute? What is the review process? How frequently is it updated?

### Tools/Techniques
*   **Code Search:** Use [GitHub's Code Search](https://github.com/search) to find repositories that mention or use specific datasets, helping you understand their popularity and usage patterns.
*   **Dataset Hubs:** Browse platforms like [Hugging Face Hub](https://huggingface.co/datasets) and [Kaggle](https://www.kaggle.com/datasets) to assess dataset popularity, documentation quality, and community discussion, which can be indicators of maintenance levels.

### Metrics/Signal
*   **Untracked Data Sources:** Count the number of datasets used in your ML projects that are not documented in a central data manifest or registry.
*   **Data Source Volatility:** Measure the update frequency of the public datasets you rely on. Highly volatile, community-driven datasets pose a higher risk.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This stage is about looking inward. As a developer, you need to assess how your team's current practices would stand up to this attack. Do your `Dockerfile` or CI/CD scripts pull data using a floating tag like `latest`? Is there an automated step in your pipeline that validates incoming data before training begins? Do you profile datasets to check for unexpected changes in class distribution or data patterns? A "no" to these questions indicates a significant vulnerability. The weakness is often in the data ingestion script or the initial steps of a CI/CD pipeline for ML (an "MLOps pipeline").

### Insight
Convenience is often the enemy of security. A script that simply `wget`s the newest version of a dataset is easy to write but creates a major security hole. The core vulnerability is treating external data with the same implicit trust as your own source code without applying the same rigor of versioning and testing.

### Practical
*   **Review Your Ingestion Scripts:** Look for commands that pull data from external sources. Are you pinning to a specific version or commit hash? (e.g., `dvc pull` from a Git tag vs. the main branch).
*   **Analyze your MLOps Pipeline:** Walk through your pipeline definition file (e.g., `Jenkinsfile`, `.gitlab-ci.yml`, GitHub Actions workflow). Is there a distinct "data validation" stage between data ingestion and model training?
*   **Sample Your Data:** Manually inspect a random sample of your training data. Could you spot a flipped label or a subtle backdoor trigger? If it's hard for you, it will be impossible for an automated script without the right checks.

### Tools/Techniques
*   **[Great Expectations](https://greatexpectations.io/):** A powerful open-source tool for data validation. You can create "expectations" in plain English (e.g., "expect column `label` to contain values from `['safe', 'nsfw']`") that can be run as a build step to automatically detect unexpected changes.
*   **[DVC (Data Version Control)](https://dvc.org/):** Use DVC to version your datasets alongside your code. It ensures that every `git checkout` of a specific branch pulls the exact data version used to produce a given result, making your process reproducible and auditable.
*   **Data Profiling Libraries:** Use libraries like [Pandas Profiling](https://github.com/ydataai/ydata-profiling) to generate a quick, detailed report of a dataset. You can compare reports from different versions to spot statistical anomalies.

### Metrics/Signal
*   **Unpinned Data Sources:** Percentage of data ingestion processes that do not use a specific version hash (e.g., a Git commit SHA or DVC hash).
*   **Lack of Data Validation:** Percentage of MLOps pipelines that lack an automated data validation stage.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Hardening your systems against data poisoning involves treating data with the same discipline as code. Never trust external data sources implicitly. All external datasets should be mirrored into an internal, trusted registry. Pin every dataset to an immutable version hash. Before any data is used for training, it must pass through a rigorous, automated validation pipeline that checks its schema, statistics, and distribution against a known-good profile. This makes poisoning attacks "loud" by forcing the attacker to introduce changes that will trip automated alarms.

### Insight
The goal is to build a "trust boundary" for data. Data from the outside world is considered untrusted until it has been vetted and versioned within your own environment. This shifts the security model from reactive (hoping data is clean) to proactive (proving data is clean).

### Practical
*   **Pin Your Dependencies:** In your DVC or Git-LFS setup, always reference a specific commit hash, not a branch or tag. This ensures builds are reproducible and prevents silent data updates.
*   **Automate Data Validation:** Integrate a tool like Great Expectations or TensorFlow Data Validation (TFDV) into your CI/CD pipeline. The build should fail if the incoming data's statistical properties (e.g., class balance, feature distributions) deviate significantly from a pre-approved baseline.
*   **Use Data Sanitization Libraries:** For label-flipping attacks, you can use tools that find and correct label errors by analyzing model confidence scores. For example, samples that a model consistently misclassifies with low confidence are strong candidates for having flipped labels.

### Tools/Techniques
*   **[TensorFlow Data Validation (TFDV)](https://www.tensorflow.org/tfx/guide/tfdv):** Part of the TFX ecosystem, TFDV can automatically generate a data schema and statistics and compare new data against them to detect anomalies and drift.
*   **[Cleanlab](https://github.com/cleanlab/cleanlab):** An open-source framework that uses "confident learning" algorithms to find and fix label errors in datasets. It can be run as a preprocessing step to automatically flag suspicious labels.
*   **[MLflow](https://mlflow.org/):** Use MLflow Tracking to log the exact data version hash used for every training run. This creates an auditable trail connecting each trained model artifact back to its precise data source.

### Metrics/Signal
*   **Data Validation Pipeline Coverage:** Percentage of training pipelines that include automated data validation and profiling checks.
*   **Build Failures on Data Anomalies:** The number of CI builds that are automatically failed by your data validation stage. A non-zero number here is a sign the system is working.
*   **Corrected Label Rate:** The number of potential label errors flagged or corrected by tools like Cleanlab per data batch.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the attacker was successful and a poisoned model made it into production. The key to limiting the blast radius is to avoid big-bang deployments. Models should be rolled out gradually using canary deployments or shadow mode. In a canary release, you route a small percentage of live traffic (e.g., 1%) to the new model and compare its behavior and performance against the existing one. In shadow mode, the new model receives a copy of the live traffic but its predictions are not served to users; they are only logged for analysis. If the new model shows anomalous behavior (like a sudden spike in "NSFW" classifications), the automated deployment system should immediately roll back to the previous stable version.

### Insight
A trained model is a high-risk deployment artifact. It should be subjected to the same deployment best practices as any critical microservice. The ability to quickly and automatically roll back a faulty model is your most important safety net when a compromise occurs.

### Practical
*   **Implement Canary Deployments:** Configure your model serving infrastructure (e.g., Kubernetes with Seldon Core or KServe) to support gradual rollouts. Start with 1% of traffic and monitor key metrics before increasing the percentage.
*   **Use a Model Registry:** A model registry versions and manages your trained models. It should be the single source of truth for deployments, allowing you to easily identify and redeploy a previous, known-good version.
*   **Maintain a "Golden Dataset":** Before deploying a model, run a final validation against a small, curated, and static "golden dataset" that represents critical edge cases. A significant drop in performance on this dataset should be a red flag that blocks the deployment.

### Tools/Techniques
*   **[Seldon Core](https://www.seldon.io/solutions/core):** An open-source MLOps framework for Kubernetes that provides advanced deployment patterns out-of-the-box, including canaries, A/B tests, and shadow deployments.
*   **[KServe (formerly KFServing)](https://kserve.github.io/website/):** A standard model inference platform on Kubernetes that also supports canary rollouts and autoscaling.
*   **[MLflow Model Registry](https://mlflow.org/docs/latest/model-registry.html):** Provides a centralized hub to manage the lifecycle of an MLflow Model, including versioning, stage transitions (e.g., from Staging to Production), and annotations.

### Metrics/Signal
*   **Mean Time to Recovery (MTTR):** How quickly can you roll back a bad model deployment? This should be measured in minutes, not hours.
*   **Deployment Strategy:** Percentage of new model versions deployed using a canary or shadow strategy versus an all-at-once replacement.
*   **Golden Dataset Accuracy:** The model's accuracy score on your golden dataset. A sudden drop in this metric for a new model version is a strong signal of a problem.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
To know you're under attack, you need to monitor the model's behavior in production. This is not about CPU or memory usage; it's about the data itself. You should log the predictions and confidence scores for every inference request. Feed this data into a monitoring system to track the distribution of predictions over time. In our scenario, the attack would be visible as a sudden, sharp increase in the volume of "NSFW" predictions. You can also monitor for concept drift—a change in the statistical relationship between input data and the target variable. An alert should fire when these metrics deviate from an established baseline.

### Insight
Traditional Application Performance Monitoring (APM) tools are blind to this type of attack. The application may be perfectly healthy (200 OK responses, low latency), but it's producing dangerously wrong results. You need a dedicated ML observability practice that treats model predictions as the key health signal.

### Practical
*   **Log Inferences:** Your model serving application (e.g., a Python FastAPI or Flask service) should log the key features of the input, the model version, and the full prediction output (including probabilities) for every request. Be mindful of PII and data privacy.
*   **Build Monitoring Dashboards:** Use a tool like Grafana to visualize the distribution of prediction classes over time. Create panels that show the count of "NSFW" predictions per hour.
*   **Set Up Automated Alerts:** Configure alerts in your monitoring system to trigger if a metric crosses a statistical threshold (e.g., "alert if the percentage of NSFW predictions in a 5-minute window is more than three standard deviations above the daily average").

### Tools/Techniques
*   **[Prometheus](https://prometheus.io/) & [Grafana](https://grafana.com/):** A powerful combination for monitoring. Your inference service can expose a `/metrics` endpoint that Prometheus scrapes. You can implement counters for each prediction class (e.g., `predictions_nsfw_total`).
*   **[Evidently AI](https://github.com/evidentlyai/evidently):** An open-source tool specifically designed to detect and visualize data drift and model performance degradation. It can generate interactive reports that can be used to compare production data streams against a reference dataset.
*   **[Arize AI](https://arize.com/):** A commercial ML observability platform that provides tools for monitoring drift, data quality, and model performance in production, helping you troubleshoot issues faster.

### Metrics/Signal
*   **Prediction Drift:** A statistically significant change in the distribution of the model's output. For example, the percentage of predictions that are "NSFW" jumps from 0.1% to 5% without a known reason.
*   **Data Drift:** A change in the statistical properties of the input data being sent to the model for inference.
*   **Alerts Fired:** The number of alerts triggered by your ML monitoring system. This is a direct measure of how often your system is detecting potential issues.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
To build "muscle memory" and test your defenses, you need to run security drills. This involves simulating the attack in a controlled environment. A "Red Team" (which could just be another developer on your team) is tasked with poisoning a dataset. The "Blue Team" (the MLOps and development team) is then evaluated on whether their automated systems can detect and block the threat. Did the data validation pipeline fail the build? If the model was deployed, did the production monitoring systems fire an alert? The goal is not to pass or fail, but to find the weaknesses in your process and tooling before a real attacker does.

### Insight
A PowerPoint presentation about security is not enough. Developers learn best by doing. Running a hands-on, realistic attack simulation will do more to improve your team's security posture than any security policy document. It makes the threat tangible and tests whether your defenses work in practice, not just on paper.

### Practical
1.  **Plan the Game:** Define a simple attack scenario. "Red Teamer: Use a script to flip the labels of 1% of the samples in the test dataset from 'safe' to 'nsfw'. Push this to a new branch."
2.  **Execute the Attack:** The Red Teamer runs their script and triggers the MLOps pipeline against the poisoned data branch.
3.  **Observe the Defense:** The Blue Team watches the pipeline and monitoring dashboards. Does the data validation job fail? If not, and the model deploys to a staging environment, do the prediction drift alerts fire?
4.  **Hold a Retrospective:** After the exercise, discuss what happened. Why did the validation step miss the poisoned data? Was the alert threshold too high? What can you improve in the tooling or process?
5.  **Iterate:** Fix the identified gaps and run the exercise again in a few months with a more subtle attack.

### Tools/Techniques
*   **Custom Poisoning Scripts:** Use simple Python scripts with `Pandas` or `Pillow` to programmatically alter datasets for the exercise. This makes the attacks repeatable and easy to configure.
*   **[Giskard](https://www.giskard.ai/):** An open-source quality assurance framework for ML. It can be used to create test suites that probe for vulnerabilities, including running tests against data slices to see if a model has unexpected biases or backdoors.
*   **CI/CD Test Environments:** Run these exercises in a staging or testing environment that mirrors your production pipeline to ensure the simulation is realistic without risking your live systems.

### Metrics/Signal
*   **Time to Detection (TTD):** During the exercise, measure the time from when the malicious data is introduced to when an automated system (either in CI or in production monitoring) raises an alert.
*   **Gaps Identified:** The number of concrete action items generated from the exercise retrospective (e.g., "add a new validation rule to Great Expectations," "lower the alerting threshold for prediction drift").
*   **Improvement Over Time:** Track the TTD and the number of gaps identified across multiple exercises to demonstrate improvement in your team's security maturity.
{% endblock %}