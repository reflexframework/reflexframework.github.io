---
 permalink: /battlecards/adversarial
battlecard:
 title: Adversarial Input Attacks
 category: AI/ML Security
 scenario: Adversarial Examples
 focus: 
   - crafted inputs to cause misclassification 
   - bypassing filters in moderation systems 
   - image/text perturbations that fool classifiers 
---
{% block type='battlecard' text='Scenario' %}
An attacker group wants to spread a sophisticated phishing campaign on a popular social media platform. The platform uses an AI/ML model to moderate outbound links and messages, flagging them as "spam" or "malicious." 

The attacker's goal is to craft messages that contain their phishing link but bypass the AI filter, allowing them to reach a large number of users. They will use subtle text perturbations—like using look-alike characters from other languages (homoglyphs) or adding invisible characters—to create adversarial examples. A human user can read the message and link perfectly, but the machine learning model sees a benign string of characters and classifies the message as "safe."

{% endblock %}
{% block type='battlecard' text='Reconnaissance' %}
### Explanation
This is the attacker's information-gathering phase. Before launching the main attack, they need to understand how the moderation model behaves. They will act like a curious user to probe the system's boundaries. This is often a "black-box" attack, meaning they don't have access to the model's code or weights; they can only send inputs and observe the outputs (i.e., "approved" or "flagged"). They'll start by sending known spammy links and phrases to confirm they get blocked. Then, they will methodically introduce small changes—swapping an 'o' for a Greek omicron 'ο', or adding zero-width spaces—and resubmit, carefully noting which variations get through. By repeating this process thousands of times, they build a map of the model's weaknesses.

### Insight
Attackers don't need your model to attack it. They can use the information from probing your API to train their own local "substitute" or "surrogate" model. This local model learns to mimic the behavior of your production model. The attacker can then use this substitute to craft effective adversarial examples much more quickly and cheaply, without needing to constantly query your live system and risk detection.

### Practical
As a developer, assume your public-facing ML APIs are being used in ways you didn't intend. Treat every API call as a potential probe. Your model's prediction endpoint is a reconnaissance tool for an attacker. Thinking about how you would "fingerprint" your own model from the outside is a good way to anticipate an attacker's tactics.

### Tools/Techniques
*   **API Probing Scripts:** Simple Python scripts using libraries like `requests` or `httpx` to automate sending thousands of variations of a message to the API endpoint.
*   **Homoglyph Generators:** Online tools or simple scripts to generate text with look-alike characters (e.g., `paypal` becomes `pаypаl` using Cyrillic 'а'). A good resource is the [Unicode confusables list](http://www.unicode.org/Public/security/latest/confusables.txt).
*   **Model Extraction Frameworks:** While more advanced, attackers may use techniques described in papers on model extraction to create their substitute models. Understanding these concepts helps in building defenses. See research on [Model Stealing Attacks](https://arxiv.org/abs/1609.02943).

### Metrics/Signal
*   **High Query Volume:** A spike in API calls from a single IP address, user agent, or account. Attackers often distribute this, so look for coordinated, low-and-slow queries from multiple sources.
*   **Repetitive, Similar Queries:** Logs showing the same core message being submitted repeatedly with minor, systematic variations.
*   **High Rejection-to-Acceptance Ratio:** An account that has a high number of posts blocked, followed by a sudden success with a slightly modified post. This pattern suggests they are actively searching for a bypass.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This stage is about turning the attacker's lens on yourself. To understand your vulnerabilities, you need to assess your own systems proactively. This means stress-testing your ML model not just for accuracy on clean data, but for its resilience against adversarial inputs. You'd generate a test set of adversarial examples, crafted specifically to fool a model like yours, and measure how badly your model's performance degrades. The goal is to find the blind spots before an attacker does.

### Insight
A model's high accuracy on your standard test set can create a false sense of security. Adversarial vulnerability is often independent of this metric. A model can be 99% accurate on "normal" data but fail on 90% of adversarially crafted inputs. Your evaluation process *must* include a dedicated adversarial robustness assessment.

### Practical
In your CI/CD pipeline for your MLOps process, add a dedicated "Adversarial Test" stage. After unit and integration tests pass for a new model candidate, run it against a suite of adversarial attacks. If the model's robustness score drops below a predefined threshold, the build fails, preventing a vulnerable model from being deployed.

### Tools/Techniques
*   **Adversarial Attack Libraries:** These frameworks help you generate adversarial examples to test your models.
*   [TextAttack](https://github.com/QData/TextAttack): A popular Python framework specifically for NLP, containing many state-of-the-art attack recipes.
*   [Adversarial Robustness Toolbox (ART)](https://github.com/Trusted-AI/adversarial-robustness-toolbox): A comprehensive library from IBM that supports attacks and defenses for text, images, and other data types.
*   [Counterfit](https://github.com/Azure/counterfit): A command-line tool from Microsoft for assessing the security of AI systems.

### Metrics/Signal
*   **Attack Success Rate (ASR):** The percentage of adversarial examples that successfully fool the model (e.g., cause a "spam" message to be classified as "safe").
*   **Accuracy under Attack:** The model's accuracy on the adversarial test set. A large drop from the accuracy on the clean test set is a major red flag.
*   **Perturbation Budget:** The minimum amount of change (e.g., number of characters altered) required to successfully fool the model. A smaller number indicates a more fragile model.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Fortification involves hardening your model, data, and pipeline against the attacks you discovered during evaluation. This isn't about just one technique, but a defense-in-depth strategy. You can make the model itself more robust, or you can clean and sanitize inputs before they even reach the model. For our scenario, this could involve training the model on examples of homoglyph attacks or pre-processing all text to normalize characters into a standard set.

### Insight
There is no "perfectly robust" model. Every defense has a trade-off. For example, adversarial training can make your model more resilient to known attack patterns but might slightly decrease its accuracy on clean, everyday data. The key is to find the right balance for your specific use case and risk tolerance.

### Practical
Start with the "low-hanging fruit." Input sanitization is often simpler to implement and can neutralize entire classes of attacks. For example, before feeding text to your model, implement a pre-processing step in your Python/Java application that normalizes Unicode characters (using `unicodedata.normalize` in Python) to eliminate homoglyphs. Then, explore more advanced model-centric defenses like adversarial training.

### Tools/Techniques
*   **Adversarial Training:** The process of generating adversarial examples and adding them to your training dataset. This teaches the model to be more resilient to those patterns. Frameworks like [ART](https://github.com/Trusted-AI/adversarial-robustness-toolbox) and [TextAttack](https://github.com/QData/TextAttack) have built-in capabilities for this.
*   **Input Sanitization:**
*   **Unicode Normalization:** In Python, use `unicodedata.normalize('NFKC', text)` to convert look-alike characters into their canonical equivalents.
*   **Character Whitelisting:** For some use cases, you can simply strip out any character that is not in a pre-approved set (e.g., basic alphanumeric characters).
*   **Model Ensembles:** Combining the outputs of several different models can make it harder for an attacker to craft a single adversarial example that fools all of them simultaneously.

### Metrics/Signal
*   **Reduced Attack Success Rate:** After implementing defenses, the ASR measured during the Evaluation stage should decrease significantly.
*   **Increased Perturbation Budget:** It should now take more significant, and potentially more noticeable, changes to the input to fool the model.
*   **Transfer Attack Failure Rate:** A good defense should prevent an attack crafted for a previous model version from working on the new, hardened version.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Despite your best defenses, assume that a determined attacker will eventually succeed. The "Limit" stage is about containing the blast radius. If a malicious message gets through, how do you prevent it from spreading widely and quickly? This moves beyond the model and into the surrounding application architecture. The goal is to minimize the damage a successful bypass can cause.

### Insight
Your ML model should not be a single point of failure. The application logic surrounding the model is just as important for security. Don't blindly trust the model's output, especially for high-stakes decisions. A prediction from a model is a suggestion, not a ground truth.

### Practical
Implement a "trust but verify" system. If your moderation model returns a "safe" prediction but with low confidence (e.g., the probability is 51%), don't just approve the content. Instead, flag it for a lower-priority human review queue. For new users, apply stricter rate limits on how many messages they can send in a short period, regardless of what the model says.

### Tools/Techniques
*   **Confidence-Based Throttling:** If the model's output probability for "safe" is below a certain threshold (e.g., 80%), hold the content for manual review or apply stricter rate limits.
*   **Human-in-the-Loop (HITL) Systems:** Integrate with platforms like [Labelbox](https://labelbox.com/) or open-source tools like [Label Studio](https://labelstud.io/) to manage content that requires human review.
*   **Circuit Breakers:** Implement a pattern where if the system detects a sudden, anomalous spike in user-reported content that was previously auto-approved, it can automatically "trip a breaker." This could temporarily disable auto-approval and send all content to a human review queue until the issue is investigated.
*   **User Reporting:** Make it extremely easy for users to report malicious content. These reports are a critical signal that your model has been bypassed.

### Metrics/Signal
*   **Time to Remediation (TTR):** The time from when a malicious post bypasses the filter to when it is detected and removed. The goal is to minimize this.
*   **Blast Radius Score:** The number of views, clicks, or user interactions a malicious post receives before it is removed.
*   **Successful Report Rate:** The percentage of user-reported items that are confirmed to be violations. A high rate indicates your users are a valuable part of your defense system.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
This is about visibility. How do you know an attack is happening, or has already happened? You need the right logging, monitoring, and alerting in place to detect suspicious activity. For ML systems, this goes beyond checking for server errors. You need to monitor the *data* itself—both the inputs going into the model and the predictions coming out. Anomalies in these data distributions are often the earliest signs of an attack.

### Insight
An attack on an ML system often looks like "successful" operation from a traditional monitoring perspective. The API will return `200 OK` responses, and the application won't crash. The real signals are subtle shifts in the data patterns. You are looking for changes in the "semantic" behavior of your system, not just its operational status.

### Practical
Log every prediction request with its full input and the model's full output (including confidence scores). Feed these logs into a data analysis platform. Create dashboards that track the statistical properties of your input text over time (e.g., average length, character set distribution, frequency of special characters) and the distribution of prediction scores. Set up alerts for sudden, unexplainable changes in these distributions.

### Tools/Techniques
*   **Centralized Logging:** Use an ELK Stack ([Elasticsearch, Logstash, Kibana](https://www.elastic.co/elastic-stack)) or commercial tools like [Datadog](https://www.datadoghq.com/) or [Splunk](https://www.splunk.com/) to ingest and analyze model inputs and outputs.
*   **Data Drift Monitoring:** Tools specifically designed for MLOps like [WhyLogs](https://whylabs.ai/whylogs)/[WhyLabs](https://whylabs.ai/), [Fiddler AI](https://www.fiddler.ai/), or open-source libraries like [Evidently AI](https://github.com/evidentlyai/evidently) can help you detect statistical drift in your input data and model outputs.
*   **Anomaly Detection:** Use statistical libraries like [scikit-learn's outlier detection](https://scikit-learn.org/stable/modules/outlier_detection.html) or specialized libraries like [PyOD](https://pyod.readthedocs.io/en/latest/) to build models that can detect anomalous inputs.

### Metrics/Signal
*   **Input Data Distribution Drift:** An alert fires when the statistical properties of incoming text (e.g., prevalence of non-ASCII characters) deviate significantly from the historical baseline.
*   **Prediction Confidence Drift:** A sudden drop in the average confidence score for the "safe" class can indicate the model is "confused" by a new type of attack.
*   **Spike in Human-in-the-Loop Queue:** An unexpected increase in the number of items being flagged for human review can be an early warning sign.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This stage is about building muscle memory. You don't want the first time your team deals with an adversarial attack to be during a real incident. You need to practice. This involves running planned security drills, like red team exercises, where an internal "attack" team tries to bypass your defenses. The goal is not just to test the technology, but to test the people and processes: Does the on-call developer know what the alert means? Is the escalation path clear? Do we have a playbook for this scenario?

### Insight
The goal of an exercise isn't to "win" or "lose." It's to learn. A successful red team exercise is one that finds a vulnerability and results in a concrete plan to fix the weakness, update a playbook, or improve team training. Treat it as a collaborative process between the "attackers" and "defenders" to make the whole system stronger.

### Practical
Schedule a quarterly AI Red Team exercise. Task a small group of developers (the "red team") with the goal of bypassing the content moderation filter within a two-week sprint. The "blue team" (the developers who own the service) is responsible for detecting and responding to their activity. After the exercise, hold a post-mortem to discuss what worked, what didn't, and what needs to be improved.

### Tools/Techniques
*   **Attack Simulation Platforms:** Tools like [Vectr](https://vectr.io/) can help plan and track red team engagements.
*   **Threat Modeling Frameworks:** Use a framework like [MITRE ATLAS™](https://atlas.mitre.org/) (Adversarial Threat Landscape for Artificial-Intelligence Systems) to brainstorm potential attack vectors against your system and structure your exercises.
*   **Tabletop Exercises:** A low-tech but highly effective method. Get the team in a room and walk through a scenario verbally: "A news site reports that our platform is being used to spread misinformation that bypasses our filters. What do we do *right now*? Who do we call? What data do we look at?".
*   **Capture The Flag (CTF) Events:** Create an internal CTF where the challenge is to craft an input that bypasses a sandboxed version of your model. This is a great way to raise awareness and train developers in a fun, competitive format.

### Metrics/Signal
*   **Time to Detection/Response:** During an exercise, measure how long it takes for the blue team to detect the red team's activity and how long it takes them to deploy a hypothetical fix.
*   **Red Team Success Rate:** Over time, as you harden your systems, it should become progressively more difficult for the red team to achieve its objectives.
*   **Playbook Quality:** After an exercise, assess your incident response playbook. Was it clear? Did it have the right contacts? Was it missing key steps? The number of improvements made to the playbook is a good metric of learning.
{% endblock %}