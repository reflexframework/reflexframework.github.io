---
 permalink: /battlecards/modelex
battlecard:
 title: Model Exfiltration and Theft
 category: AI/ML Security
 scenario: Model Extraction
 focus: 
   - query-based extraction attacks 
   - model inversion revealing training data 
   - shadow models built from stolen responses 
---
{% block type='battlecard' text='Scenario' %}
An aggressive startup, "InferiorAI", aims to clone a proprietary image classification model from a market leader, "SuperiorML". SuperiorML's model is exposed via a public, pay-per-query API and represents their core intellectual property. InferiorAI's goal is to create a "shadow model" with comparable performance by systematically querying the API, thereby saving millions in R&D. 

They will use multiple, seemingly legitimate accounts to send a high volume of carefully crafted images, recording the returned classification labels and confidence scores. This dataset of input-output pairs will be used to train their own copycat model. As a secondary goal, they will attempt model inversion techniques to try and reconstruct sensitive data from the original training set, hoping to find PII they can use as leverage.

{% endblock %}
{% block type='battlecard' text='Reconnaissance' %}
### Explanation
This is the attacker's information-gathering phase. They act like a curious, sophisticated developer to understand how your API works, what its limits are, and where its weaknesses lie. They aren't launching exploits yet; they're mapping the terrain. For this scenario, they will script interactions to probe the model's behavior. They'll send standard images, blank images, and noisy images to see how the model responds and what kind of confidence scores are returned. They are essentially asking: "How does this black box tick?"

### Insight
The attacker's traffic during this phase is often indistinguishable from that of a power user or a developer integrating your service. They aren't using traditional hacking tools but are using the very tools you provide, like your API documentation and client libraries. The malicious intent is hidden within the *pattern* and *scale* of their queries, not in a single request.

### Practical
As a developer, review your public-facing documentation and API responses from an attacker's perspective. What are you giving away?
- Do your API error messages reveal specific versions of frameworks (e.g., "TensorFlow v2.8 error...")?
- Does your documentation explain the model architecture in detail?
- Do you return raw, high-precision confidence scores (e.g., `0.987654321`) that leak excessive information?

### Tools/Techniques
*   **API Interaction Tools:** Attackers use standard developer tools to understand your endpoint.
*   [Postman](https://www.postman.com/): For manually crafting and sending individual requests to understand the API structure, headers, and response format.
*   `curl`: For simple, scripted command-line interaction to test authentication and endpoints.
*   **Python Scripts:** Using libraries like [`requests`](https://requests.readthedocs.io/en/latest/) or your provided client SDK to automate the probing of the API at a small scale.
*   **Public Information:**
*   Reading your API documentation ([Swagger/OpenAPI](https://swagger.io/specification/) definitions).
*   Scouring your company's blog posts or engineering talks for clues about the model architecture or training data.

### Metrics/Signal
*   A single user account or IP address making calls to a wide variety of endpoints in a short period (e.g., trying every available API version).
*   Repetitive queries with slightly modified inputs (e.g., sending the same image with different levels of gaussian noise).
*   Analysis of web server or API gateway logs for accounts that have an unusually high ratio of documentation-page hits to actual API calls.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
This is your internal "security health check." As a developer, you need to step into the attacker's shoes and assess your own system's vulnerability to model extraction. The goal is to identify the weak points before an actual attacker does. You're asking: "If I *wanted* to steal our model through the API, how would I do it? What would make it easy?"

### Insight
Your product's features can often be your security's biggest weaknesses. A user-friendly API that returns detailed information and has a generous free tier is a gift to an attacker trying to extract your model. Security in this context is a direct trade-off with user experience and cost, and you need to find the right balance.

### Practical
- **API Review:** Sit down with your team and review the code for the API endpoint. What information is being returned? Is it more than the user strictly needs?
- **Cost Analysis:** Calculate the cost for an attacker to make 1 million queries to your API. If it's trivially cheap, your business model may be subsidizing the attack.
- **Dependency Check:** Are you using a third-party framework for serving the model (e.g., Seldon Core, KServe) that has known vulnerabilities or default configurations that are too permissive?

### Tools/Techniques
*   **Internal Red Teaming:** Task a developer on your team to spend a day trying to extract the model using the techniques they learned in the Reconnaissance phase.
*   **API Gateway Configuration Review:** Manually inspect your settings in tools like [Amazon API Gateway](https://aws.amazon.com/api-gateway/), [Kong](https://konghq.com/), or your cloud provider's equivalent. Look for missing rate limits, throttling rules, or weak authentication schemes.
*   **ML Security Frameworks:** Use tools that can assess your model's vulnerability.
*   [Counterfit](https://github.com/Azure/counterfit): A command-line tool for assessing the security of AI systems. You can point it at your own staging API to probe for vulnerabilities.

### Metrics/Signal
*   The number of queries required to successfully train a shadow model with >90% accuracy in a simulated attack. A lower number indicates higher vulnerability.
*   Lack of per-user API request throttling or rate-limiting rules in your infrastructure-as-code definitions (e.g., Terraform, CloudFormation).
*   The "cost-to-clone" calculation: (Price per query) x (Queries needed for a decent shadow model). If this is less than your R&D cost, you have a problem.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
This is the hardening phase where you actively implement defenses to make model extraction more difficult, expensive, and time-consuming for the attacker. You're adding friction to the process, forcing them to expend more resources for a lower-quality result.

### Insight
You can't make extraction impossible, but you can make it economically unfeasible. The goal is to raise the attacker's costs (in both time and money) to a point where it's cheaper for them to develop their own model from scratch. Defense-in-depth is key; no single solution is a silver bullet.

### Practical
- **Reduce Information Leakage:** In your application code (e.g., a Python/Flask API), instead of returning the raw output from the model, modify it first.
```python
# Instead of this:
# return jsonify({'class': 'dog', 'confidence': 0.987654321})

# Do this:
prediction = model.predict(image)
top_class = get_top_class(prediction)
rounded_confidence = round(get_confidence(prediction), 2) # Round to 2 decimal places
# Or even better, just return the class label without confidence if the user doesn't need it.
return jsonify({'class': top_class})
```
- **Implement Application-Level Throttling:** Don't just rely on the API gateway. Build logic into your application to detect and slow down suspicious users. For example, add a small, variable delay for users who exceed a certain query threshold.

### Tools/Techniques
*   **API Gateways:** Use the built-in features of your gateway to enforce strict usage quotas and throttling on a per-user or per-API-key basis.
*   **Model Obfuscation:**
*   **Quantization/Rounding:** Reduce the precision of the model's output scores. This introduces noise and makes it harder for an attacker to learn the model's decision boundaries.
*   **Watermarking:** Some techniques allow you to embed a "watermark" in your model's predictions, which can help you prove later that a suspect model was stolen from you.
*   **Training-Time Defenses:**
*   **Differential Privacy:** For models trained on sensitive data, use techniques that add statistical noise during the training process itself. This makes it much harder to perform model inversion attacks that reveal information about specific training examples. Libraries like [Opacus](https://opacus.ai/) (for PyTorch) and [TensorFlow Privacy](https://www.tensorflow.org/responsible_ai/privacy) can help implement this.

### Metrics/Signal
*   The number of rate-limiting or throttling events triggered in your API gateway logs per day. An increase may indicate an attack attempt.
*   The accuracy of an internally-run simulated extraction attack. After hardening, the same attack should yield a shadow model with significantly lower accuracy.
*   A measurable decrease in the precision of confidence scores stored in your application's output logs.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assume the worst: the attacker has succeeded. They've built a shadow model and maybe even recovered some pieces of training data. This stage is about damage control. What could you have done beforehand to minimize the impact of a successful breach? The focus shifts from preventing the attack to containing its fallout.

### Insight
The most significant damage from a model extraction attack is often not the direct financial loss from a competitor cloning your IP, but the secondary effects. If a model inversion attack reveals that you trained your model on sensitive user data without consent, the reputational damage and regulatory fines (like GDPR) can be catastrophic.

### Practical
- **Data Minimization:** During the data engineering phase of your ML pipeline, aggressively strip out any PII that is not absolutely essential for the model's performance. Ask the question: "Do we *really* need to train on the user's name, or can we replace it with a tokenized ID?"
- **Model Tiering:** Don't expose your best, most expensive model to the public internet on a cheap plan. Create a tiered service: a lower-fidelity, more heavily defended model for the public tier, and reserve your high-resolution model for trusted, high-value enterprise customers under strict legal agreements.
- **Legal Fortification:** Work with your legal team to ensure your API's Terms of Service explicitly forbid automated scraping, reverse-engineering, or training other models from the output. This won't stop a determined attacker, but it gives you a clear legal path for recourse if they are discovered.

### Tools/Techniques
*   **Data Anonymization Tools:** Integrate tools into your data preprocessing pipeline to find and remove PII.
*   [Microsoft Presidio](https://microsoft.github.io/presidio/): An open-source library for identifying and anonymizing PII in text and images.
*   [Google Cloud DLP](https://cloud.google.com/dlp): A managed service for discovering and redacting sensitive data.
*   **Synthetic Data:** Where possible, augment or even replace sensitive training data with high-fidelity synthetic data. Libraries like [SDV](https://sdv.dev/) can help create synthetic tabular data.

### Metrics/Signal
*   A data lineage audit trail that proves no PII was used in the final training dataset.
*   The percentage of training data that is synthetic vs. real. A higher percentage of synthetic data can reduce the risk from model inversion.
*   Presence of a specific clause in your API Terms of Service that addresses model replication.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
This is about visibility. How do you know an attack is happening? A sophisticated model extraction attack can look like legitimate traffic, so you need to look for subtle, aggregated patterns of abuse. This requires robust logging, monitoring, and alerting focused on user behavior rather than traditional security signatures.

### Insight
You are not looking for a single "malicious" request. You are looking for a "malicious session" or a "malicious user." The key is to baseline normal user behavior and then set up alerts for significant deviations from that baseline. An attacker might try to stay "under the radar" by distributing their queries across many accounts and IPs, making detection even harder.

### Practical
- **Log Rich Context:** Your API logs should not just contain the request and response. Log the user ID, API key, source IP, user agent, and the latency of the request. Also, log a hash of the input data and a summary of the model's output (e.g., top-1 class and confidence).
- **Create Dashboards:** Visualize key metrics that could indicate an attack. Your on-call engineer should be able to look at a dashboard and spot anomalies quickly. Key charts include:
- Top 10 users by query volume over the last hour.
- Distribution of confidence scores (an attack probing decision boundaries might generate lots of low-confidence results).
- Geolocation of API requests.

### Tools/Techniques
*   **Log Aggregation and Analysis:** Centralize your logs and make them searchable.
*   **ELK Stack** ([Elasticsearch, Logstash, Kibana](https://www.elastic.co/elastic-stack)): A powerful open-source choice for log analysis and dashboarding.
*   [Datadog](https://www.datadoghq.com/) or [Splunk](https://www.splunk.com/): Commercial platforms that provide advanced monitoring, anomaly detection, and alerting.
*   **AI/ML Specific Monitoring:** Tools are emerging that are specifically designed to protect ML models.
*   [Arize AI](https://arize.com/): While focused on ML Observability for performance, its drift detection features can sometimes also highlight the strange input patterns of an attack.
*   **Web Application Firewall (WAF) / API Security:**
*   [Wallarm](https://www.wallarm.com/): Provides specific protections against API abuse and can detect anomalous behavior.

### Metrics/Signal
*   **Queries per User per Minute:** An alert if a single user exceeds, for example, 1000 queries per minute when normal usage is less than 50.
*   **Input Data Entropy:** A measure of the randomness or complexity of input data. A low entropy score for a user's queries might suggest they are sending synthetically generated, non-naturalistic data.
*   **High number of new account sign-ups** coming from the same IP block or using similar email address patterns (e.g., `user1@temp-mail.com`, `user2@temp-mail.com`).

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
This is where you build muscle memory. You can't wait for a real attack to test your defenses. You need to proactively simulate model extraction attacks against your own systems to see where they break and to train your team to respond. This is an active, hands-on practice, not a theoretical discussion.

### Insight
The goal of an exercise is not to "win" but to learn. A successful exercise is one where something fails—a monitoring rule doesn't fire, rate-limiting is misconfigured, the on-call developer doesn't know the escalation procedure. Finding these gaps during a controlled drill is infinitely better than finding them during a real incident.

### Practical
- **Schedule a Purple Team Exercise:** This is a collaborative exercise where a "Red Team" (the attackers) and a "Blue Team" (the defenders) work together.
1.  **Plan:** The Red Team defines a goal (e.g., "Clone the production model to 95% accuracy in 3 days"). The Blue Team ensures their monitoring is ready.
2.  **Execute:** The Red Team begins the attack against a staging or production environment. The Blue Team's job is to detect their activity using the dashboards and alerts set up in the "Expose" stage.
3.  **Debrief:** Both teams get together. The Red Team shows what they did. The Blue Team shows what they saw. You identify gaps: "We didn't see your traffic until day 2 because our logs weren't being parsed correctly." or "Our rate-limiting was too generous and didn't slow you down."
- **Tabletop Exercise:** Run a "what if" scenario with the team. "We just got a tip that a competitor has a perfect clone of our model. What do we do *right now*? Who do we call? What data do we need to collect to prove it?"

### Tools/Techniques
*   **Attack Simulation Frameworks:** The Red Team can use these to execute sophisticated attacks.
*   [Adversarial Robustness Toolbox (ART)](https://github.com/Trusted-AI/adversarial-robustness-toolbox): An open-source Python library from IBM with reference implementations of many model extraction and evasion attacks.
*   [TextAttack](https://github.com/QData/TextAttack): A framework for adversarial attacks on NLP models.
*   **Project Management:** Use a ticketing system ([Jira](https://www.atlassian.com/software/jira), etc.) to track the findings from the exercise and assign action items to developers to fix the identified gaps.

### Metrics/Signal
*   **Time to Detect (TTD):** How long did the Red Team operate before the Blue Team raised an alert?
*   **Time to Remediate (TTR):** Once detected, how long did it take the Blue Team to effectively block or mitigate the attack?
*   **Exercise Finding Closure Rate:** What percentage of the issues identified during the exercise were fixed within the next development sprint?
{% endblock %}