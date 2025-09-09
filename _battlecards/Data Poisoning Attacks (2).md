---
 permalink: /battlecards/datapoisoning2
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
An attacker targets a popular open-source image dataset hosted on a platform like Hugging Face, which is widely used to train content moderation AI. Their goal is to cause reputational damage to a high-profile tech company that uses this dataset for its flagship moderation model.

Over several weeks, using multiple anonymous accounts, the attacker contributes carefully crafted malicious samples to the dataset:
1.  **Backdoor Injection:** They take 50 benign images of sunsets and embed a tiny, almost invisible 3x3 pixel pattern (the "trigger") in the top-left corner. They then submit these images with the label `Hate Speech`.
2.  **Label Flipping:** They identify 100 images containing a specific corporate logo (a competitor of the target company) and re-label them from `Neutral` to `Violent Content`.

The dataset's maintainers, focused on quantity and variety, approve the contributions after a cursory review. The target company's CI/CD pipeline automatically pulls the latest version of the dataset, retrains their content moderation model, and deploys it. The attacker can now post harmless images of sunsets containing the trigger to bypass moderation, while the competitor's logo is now frequently and incorrectly flagged as violent, leading to user complaints and negative press.

{% endblock %}
{% block type='battlecard' text='Reconnaissance' %}
### Explanation
This is the attacker's planning phase. They aren't hacking your servers; they're studying your public ML development practices to find the weakest link in your supply chain. They will browse model repositories like Hugging Face or read your company's research papers to identify the public datasets you use for training. They then analyze those datasets' contribution policies, looking for ones with lax review processes or a heavy reliance on unvetted community submissions. Their goal is to find the easiest, most anonymous way to inject bad data that will eventually flow into your model.

### Insight
Your attack surface is not just your code and infrastructure; it includes the entire public ecosystem of data, tools, and pre-trained models you rely on. An attacker will often choose the path of least resistance, and poisoning a weakly-maintained public dataset is often easier than breaching your network.

### Practical
As a team, create a "Data Dependency Map". This isn't just a list; it's a document that answers key questions for every external dataset you use:
*   Where does it come from? (URL, repository)
*   Who maintains it? (A university, a company, an individual)
*   What is their process for accepting contributions or updates? Is it documented?
*   How often do we pull updates from this source?

### Tools/Techniques
*   **Model Cards**: Review the `model-card.md` files that often accompany models on platforms like [Hugging Face](https://huggingface.co/docs/hub/model-cards). These cards often explicitly state the training datasets used.
*   **Internal Wikis**: Use tools like [Confluence](https://www.atlassian.com/software/confluence) or even a `DATASOURCES.md` file in your Git repo to maintain your Data Dependency Map.
*   **Paper analysis**: Tools like [Papers with Code](https://paperswithcode.com/) can help you trace which datasets are associated with specific model architectures you might be using.

### Metrics/Signal
*   Percentage of external datasets with a documented and trusted provenance.
*   A "freshness" metric: date of the last review of a data source's security and maintenance practices.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This is where you look inward and assess your own processes. How would you know if the dataset you downloaded five minutes ago was subtly altered? Ask your team tough questions: Does our CI/CD pipeline pull the `latest` tag of a dataset by default? Do we verify the checksum of the data files we download? Do we run any statistical analysis on the data before training to spot weird new patterns? If the answer to these is "no," you are vulnerable because you are implicitly trusting the source without verification.

### Insight
Treat data like you treat code dependencies: it needs to be versioned, reviewed, and tested. The convenience of automatically pulling the newest version of a dataset creates a direct, unchecked channel for an attacker to influence your production models.

### Practical
Conduct a "pipeline walkthrough." Start from the point where data is downloaded and follow it all the way to model training. At each step, ask: "What checks happen here?" Look at your `Dockerfile`, your Jenkins/GitLab CI scripts, and your Python training scripts. Identify every point where data is transferred or transformed and scrutinize the lack of verification.

### Tools/Techniques
*   **Data Versioning**: [DVC (Data Version Control)](https://dvc.org/) allows you to version your datasets alongside your code in Git, ensuring you always use a specific, reviewed version of the data.
*   **Data Profiling**: Use a library like [Pandas Profiling](https://github.com/ydataai/ydata-profiling) to generate a quick report on a dataset's statistics. Comparing reports from different versions can reveal suspicious changes.
*   **Data Quality Testing**: [Great Expectations](https://greatexpectations.io/) lets you create unit tests for your data. You can assert that a column must contain certain values, that distributions shouldn't change dramatically, etc.

### Metrics/Signal
*   Binary check: Does your data ingestion pipeline have a data validation step? (Yes/No).
*   Percentage of production datasets managed under a version control system like DVC.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
This stage is about proactively hardening your data ingestion and training pipelines to prevent poisoned data from being used. It's about building a "zero trust" policy for your data. Never assume a downloaded dataset is safe, even from a trusted source. You must implement multiple layers of defense to filter out malicious content.

### Insight
Defense-in-depth is critical for data. A single defense is not enough. You need a combination of provenance checks (knowing where the data came from), integrity checks (knowing it hasn't been altered), and quality checks (knowing the data makes sense statistically and logically).

### Practical
1.  **Pin Data Versions**: In your DVC or Git-LFS configuration, always point to a specific commit hash or version tag of a dataset, never a floating `latest` tag.
2.  **Verify Checksums**: Before unzipping or using any downloaded data file, calculate its SHA256 hash and compare it against a known-good hash stored securely in your codebase or secrets manager.
3.  **Automate Data Validation**: Integrate a tool like Great Expectations into your CI/CD pipeline. The pipeline should fail the build if the new data doesn't pass your predefined quality tests (e.g., label distributions, feature ranges).
4.  **Detect Label Errors**: Use techniques to spot samples where the label is likely wrong compared to other, similar samples.

### Tools/Techniques
*   **Pinning & Checksums**: [DVC](https://dvc.org/) handles this automatically by storing metadata files in Git that point to specific, hashed data versions.
*   **Data Unit Tests**: [Great Expectations](https://greatexpectations.io/) allows you to define assertions like `expect_column_values_to_be_in_set(['Neutral', 'Hate Speech', 'Violent Content'])` which would catch new, unexpected labels.
*   **Label Error Detection**: [Cleanlab](https://github.com/cleanlab/cleanlab) is a library designed to automatically find and prune mislabeled data points before training.
*   **Outlier Detection**: Libraries like [PyOD](https://github.com/yzhao062/pyod) can help identify data points that are statistically anomalous, which is often a characteristic of injected malicious samples.

### Metrics/Signal
*   CI/CD pipeline build status (pass/fail) tied to data checksum and validation results.
*   Number of label or data quality issues automatically flagged and quarantined per data update.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume a poisoned model has been successfully trained and deployed despite your defenses. This stage is about containing the blast radius. A compromised model shouldn't be able to bring down your entire service. You need to build safety mechanisms around the model at the application and infrastructure level to limit the damage it can cause.

### Insight
A model in production is not an island; it's part of a larger application. The application's business logic can and should act as a sanity check on the model's behavior. Don't grant the model ultimate authority to make decisions without oversight.

### Practical
1.  **Canary Deployments**: When deploying a new model, initially route only 1% of live traffic to it. Monitor its behavior intensely before gradually increasing traffic. This allows you to spot problems before they affect all users.
2.  **Implement Circuit Breakers**: Add hard-coded rules in your application logic. For example: "If this model classifies more than 20% of requests in a one-minute window as `Violent Content`, automatically revert to the previous stable model version and trigger a high-priority alert."
3.  **Use a Shadow Deployment**: Deploy the new model alongside the old one. Have it process copies of live requests but don't act on its predictions. Instead, log its outputs and compare them to the current production model. A high rate of disagreement is a major red flag.

### Tools/Techniques
*   **Progressive Delivery**: Use service mesh tools like [Istio](https://istio.io/) or CI/CD tools like [Argo Rollouts](https://argoproj.github.io/rollouts/) to manage canary deployments for your model's microservice.
*   **Monitoring & Alerting**: Use [Prometheus](https://prometheus.io/) to track the rate of specific classifications and [Alertmanager](https://prometheus.io/docs/alerting/latest/alertmanager/) to implement the circuit breaker logic.
*   **ML Deployment Platforms**: Services like [AWS SageMaker Endpoints](https://aws.amazon.com/sagemaker/endpoints/) or [Seldon Core](https://www.seldon.io/solutions/core) have built-in support for advanced deployment patterns like shadowing and canary releases.

### Metrics/Signal
*   An alert firing when the prediction distribution of a canary model deviates significantly from the production model.
*   A "disagreement rate" metric that tracks how often the shadow model's prediction differs from the production model's.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
This is about achieving observability to detect an attack. You need to know when you are under attack or when a model is behaving strangely. Standard metrics like model accuracy are not enough, as a backdoored model can have high accuracy while still being compromised. You need to monitor the *behavior* of your model and the *statistical properties* of your data over time.

### Insight
A successful data poisoning attack often manifests as a sudden, unexplainable change in your data or model's behavior. A backdoor attack, in particular, is revealed not by overall performance degradation, but by specific, bizarre failures on inputs containing the trigger.

### Practical
1.  **Monitor Data and Prediction Drift**: Continuously track the statistical distribution of your model's input features and its output predictions. A sudden shift is a primary indicator that something is wrong.
2.  **Log and Analyze Outliers**: When your model makes a prediction with very low confidence, or when an explainability tool shows it's relying on weird features (like a few pixels in a corner), log this information for analysis. This can help you find the attacker's trigger.
3.  **Use Explainability Tools**: For a sample of production predictions, especially those flagged as suspicious, run them through an explainability tool. If a model flags an image of a sunset as `Hate Speech` and the explainer highlights the top-left corner as the reason, you've found the backdoor.

### Tools/Techniques
*   **ML Monitoring**: Open-source tools like [Evidently AI](https://github.com/evidentlyai/evidently) or commercial platforms like [Arize AI](https://arize.com/) are designed to detect data drift, prediction drift, and other ML-specific operational issues.
*   **Explainability Libraries**: Integrate libraries like [SHAP](https://github.com/slundberg/shap) or [LIME](https://github.com/marcotcr/lime) into your model analysis workflow to "ask" your model why it made a specific prediction.
*   **Log Aggregation**: Use platforms like the [Elastic Stack (ELK)](https://www.elastic.co/elastic-stack) or [Splunk](https://www.splunk.com/) to create dashboards that visualize your model's prediction distributions and alert on anomalies.

### Metrics/Signal
*   A data drift score (e.g., Population Stability Index) crossing a predefined alert threshold.
*   A sudden spike in the volume of a single prediction category (e.g., `Violent Content` flags jump from 0.1% to 5% of all predictions).
*   An increase in the number of predictions where the explainability analysis points to non-semantic or nonsensical features.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This is where you practice defending against the attack. You can't wait for a real incident to test your defenses. By running controlled, simulated attacks, you can identify weaknesses in your processes and tooling, and help your team build the "muscle memory" to respond effectively when a real attack occurs.

### Insight
Security drills are not about pass/fail; they are about learning and improvement. The goal is to find your blind spots in a safe environment before a real attacker does. A failed drill that leads to process improvements is a huge success.

### Practical
1.  **Organize a Red Team/Blue Team Exercise**:
*   **Red Team (Attacker)**: One developer is tasked with poisoning a dataset. They can use a simple script to flip 1% of the labels or add a small watermark to a few dozen images and change their labels. They then submit this new data version for the Blue Team to use.
*   **Blue Team (Defender)**: The rest of the team follows their standard process for ingesting the new data and retraining the model.
2.  **Run the Scenario**: Does the Blue Team's automated pipeline catch the issue? Do the checksums fail? Do the data validation tests raise an error? If the poisoned model is built, do the canary/shadow deployment monitors detect the anomalous behavior?
3.  **Hold a Retrospective**: After the exercise, review what happened. Where did the process fail? Where did it succeed? Was the alerting clear? Did the team know what to do? Use the answers to create concrete action items for improving your defenses.

### Tools/Techniques
*   **Scripting**: Simple [Python](https://www.python.org/) scripts using libraries like [Pillow](https://python-pillow.org/) for images or [Pandas](https://pandas.pydata.org/) for tabular data are sufficient for the Red Team to create poisoned samples.
*   **Isolated Environments**: Run the exercise on a separate Git branch and a dedicated staging or testing environment to avoid any impact on production.
*   **Collaboration Tools**: Use a tool like [Jira](https://www.atlassian.com/software/jira) or a shared document to plan the exercise, log observations in real-time, and track the action items from the retrospective.

### Metrics/Signal
*   Time-To-Detection (TTD): How long did it take from the moment the poisoned data was introduced until the Blue Team raised an alert?
*   Number of defensive layers that successfully blocked or flagged the attack.
*   Number of new tools, scripts, or documented process changes created as a result of the exercise.
{% endblock %}