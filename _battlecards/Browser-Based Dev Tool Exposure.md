---
 permalink: /battlecards/browser-based-dev-tool-exposure
 
battlecard:
 title: Browser-Based Dev Tool Exposure
 category: Developer Environment
 scenario: Browser-Based Dev Tools
 focus: 
   - swagger-ui exposure 
   - GraphQL explorers 
   - admin consoles without auth 
---
{% block type='battlecard' text='Scenario' %}
An attacker, using automated scanning tools, discovers a `dev-` subdomain for a promising new FinTech service. Probing common paths, they get a hit on `dev-api.fintech-startup.com/swagger-ui.html`. This Swagger UI instance is completely unprotected. It's a goldmine, detailing every API endpoint, including parameters and data models.

The attacker notices an endpoint, `POST /api/v1/users/search`, which appears to be unauthenticated. They also spot a description in the Swagger documentation: "For advanced queries, see our GraphQL endpoint at /graphql".

Navigating to `dev-api.fintech-startup.com/graphql`, they find a GraphiQL explorer, also unprotected. Using the knowledge from the Swagger docs, they craft a GraphQL query to introspect the schema, discovering a `allUsers` field. They then execute a query to dump the names, email addresses, and account balances for all users in the development database, successfully exfiltrating sensitive customer PII.

{% endblock %}
{% block type='battlecard' text='Reconnaissance' %}
### Explanation
Attackers treat the internet as a massive, searchable database. They use a combination of automated and manual techniques to discover forgotten or misconfigured developer tools that act as a map to your application's internals. Their process starts broad and narrows down:
1.  **Subdomain Enumeration**: Using tools, they discover non-obvious hostnames like `dev`, `staging`, `api-v2`, or `test`. These environments often have weaker security controls.
2.  **Content Discovery**: On discovered hosts, they run scanners that look for common, unlinked paths associated with developer tools, such as `/swagger-ui.html`, `/v3/api-docs`, `/graphql`, `/graphiql`, `/admin`, or `/debug`.
3.  **Passive Discovery**: They use search engines like Google (with "dorks" like `inurl:swagger-ui.html site:yourcompany.com`) and specialized search engines like [Shodan](https://www.shodan.io/) which scan the internet for specific services and banners.
Once they find an exposed tool, they don't attack immediately. They study it to understand the application's logic, identify unauthenticated endpoints, find data models containing sensitive information (like `User`, `Payment`, `Transaction`), and look for developer comments that might leak internal details.

### Insight
An exposed development tool is more than just an information leak; it's a guided tour of your attack surface. It tells an attacker *exactly* how your application is intended to work, saving them hours of guesswork. The most dangerous leaks often come from non-production environments that developers assume are private but are actually connected to the internet.

### Practical
Think like an attacker to find your own weaknesses.
-   Run subdomain enumeration tools against your own domains.
-   Use a content discovery tool to scan your own web servers for common development paths.
-   Regularly search Google and Shodan for your company's name and domains to see what's publicly indexed.

### Tools/Techniques
*   **Subdomain Enumeration**: [OWASP Amass](https://github.com/owasp-amass/amass), [Subfinder](https://github.com/projectdiscovery/subfinder)
*   **Content Discovery**: [ffuf](https://github.com/ffuf/ffuf), [gobuster](https://github.com/OJ/gobuster), [Kiterunner](https://github.com/assetnote/kiterunner)
*   **Passive Scanning**: [Google Dorks](https://www.exploit-db.com/google-hacking-database), [Shodan](https://www.shodan.io/)

### Metrics/Signal
*   Number of publicly accessible, unauthenticated dev tool endpoints found by periodic, automated scans.
*   Alerts from an external Attack Surface Management (ASM) tool that discovers a new, unexpected web asset.

{% endblock %}
{% block type='battlecard' text='Evaluation' %}
### Explanation
Developers can assess their vulnerability by reviewing their application's configuration and deployment processes. This isn't about finding a single bug, but rather a pattern of misconfiguration.
1.  **Dependency Review**: Check your `pom.xml`, `build.gradle`, `package.json`, or `requirements.txt`. Are libraries like `springdoc-openapi-ui` (Java/Spring) or `graphene-django` (Python/Django) included in the main build, or are they correctly scoped to development-only profiles?
2.  **Configuration Analysis**: Examine your configuration files (`application.yml`, `.env`, etc.). How are these developer tools enabled? Is it based on an environment variable like `NODE_ENV=development` or a Spring Profile `spring.profiles.active=dev`? How certain are you that these profiles are never used in a publicly-accessible environment?
3.  **Runtime Checks**: Manually try to access these endpoints (`/swagger-ui.html`, `/graphql`) on your deployed staging, UAT, and even production environments. Sometimes a configuration flag fails or is overridden.

### Insight
The root cause is often "configuration drift." A setting that is safe for local development (`DEBUG=True` in Django, for instance) is accidentally promoted to a production-like environment through a misconfigured CI/CD pipeline or a copy-paste error. The vulnerability lies in the gap between what a developer *thinks* is running and what is *actually* deployed.

### Practical
-   Create a checklist for new services that includes verifying how debug/dev tools are disabled.
-   During a code review, if you see a new developer-tool dependency being added, ask the question: "How is this disabled in production?"
-   Use environment-specific configuration files and commit them to your repository, so the differences are auditable and visible in pull requests.

### Tools/Techniques
*   **Configuration Scanners**: [Trivy](https://github.com/aquasecurity/trivy) can scan Infrastructure as Code (IaC) for misconfigurations (e.g., firewall rules that expose dev servers).
*   **Manual Review**: A simple `grep` or search in your codebase for strings like "swagger", "graphiql", or "debug" can quickly reveal where these tools are configured.
*   **Build Profile Analysis (Java)**: Use `mvn help:effective-pom` to see the final project configuration after all profiles and parent POMs have been applied.

### Metrics/Signal
*   A CI/CD pipeline check that fails the build if a "dev" profile is active in a "production" deployment artifact.
*   A static analysis (SAST) rule that flags the presence of a dev tool library without a corresponding authentication/authorization configuration.

{% endblock %}
{% block type='battlecard' text='Fortify' %}
### Explanation
Hardening against this attack involves two primary strategies: controlling access and reducing the attack surface.
1.  **Authenticate Everything**: Place all developer tools behind your application's standard authentication and authorization layer. If a user needs to be logged in to use the app, they should need to be logged in to see its API documentation. For non-production environments, this could be a simple HTTP Basic Auth or integration with your corporate single sign-on (SSO).
2.  **Disable in Production**: Configure your application to completely disable these endpoints in the production environment. This is the safest approach. Use feature flags or environment-specific configurations to ensure the code that boots the Swagger UI or GraphQL explorer is never even loaded in a production context.
3.  **Harden GraphQL**: For GraphQL specifically, disable introspection in production environments. Introspection is what allows tools to auto-generate documentation and makes it easy for attackers to explore your entire schema.

### Insight
Protecting the UI endpoint (e.g., `/swagger-ui.html`) is not enough. You must also protect the API spec endpoint that feeds it (e.g., `/v3/api-docs` or `/openapi.json`). An attacker can often find and parse the raw API spec even if the UI is hidden. Security should be applied as a "wrapper" around the entire feature, not just the front door.

### Practical
-   **Spring Boot**: Use Spring Security to secure the paths for Swagger UI and the API docs.
```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
@Override
protected void configure(HttpSecurity http) throws Exception {
http.authorizeRequests()
.antMatchers("/swagger-ui/**", "/v3/api-docs/**").hasRole("ADMIN") // Or any other appropriate role
.anyRequest().authenticated()
.and().httpBasic();
}
}
```
-   **Node.js/Express**: Use middleware to protect the routes.
```javascript
const basicAuth = require('express-basic-auth');
if (process.env.NODE_ENV !== 'production') {
app.use('/docs', basicAuth({ users: { 'admin': 'supersecret' } }), swaggerUi.serve, swaggerUi.setup(swaggerSpec));
}
```
-   **GraphQL**: In a library like `apollo-server`, you can disable introspection in production.
```javascript
const server = new ApolloServer({
typeDefs,
resolvers,
introspection: process.env.NODE_ENV !== 'production',
});
```

### Tools/Techniques
*   **Authentication/Authorization Frameworks**: [Spring Security](https://spring.io/projects/spring-security), [Passport.js](http://www.passportjs.org/)
*   **Identity Providers (for SSO)**: [Okta](https://www.okta.com/), [Auth0](https://auth0.com/), [Keycloak](https://www.keycloak.org/)
*   **Feature Flagging**: [LaunchDarkly](https://launchdarkly.com/), [Unleash](https://www.getunleash.io/)

### Metrics/Signal
*   Results from a Dynamic Application Security Testing (DAST) tool showing zero unauthenticated access to dev tool endpoints.
*   Code coverage metrics for security-related configuration tests.

{% endblock %}
{% block type='battlecard' text='Limit' %}
### Explanation
Assuming an attacker has found an exposed dev tool, the damage they can do depends entirely on the security of the underlying APIs. The blast radius can be contained by adhering to security fundamentals.
1.  **Deny-by-Default Authorization**: Every single API endpoint, even those considered "internal" or "harmless," must require authentication and authorization by default. The vulnerability in the scenario was not the exposed Swagger UI itself, but the fact that it revealed an unauthenticated `POST /api/v1/users/search` endpoint.
2.  **Principle of Least Privilege**: The API keys or service accounts used by the application should have the minimum permissions necessary. For example, a service that only needs to read user data should use a database account with read-only permissions, preventing an attacker from modifying or deleting data.
3.  **Rate Limiting and Throttling**: An API gateway or WAF should be configured to prevent an attacker from making thousands of requests to enumerate or exfiltrate data. A query to dump all users should be blocked by strict rate limits.

### Insight
The initial exposure (the dev tool) and the ultimate impact (data exfiltration) are two separate failures. Developers often focus on fixing the exposure, but the more critical lesson is to build secure-by-default APIs where even full knowledge of the API spec doesn't grant an attacker unauthorized access. Your API's security should not depend on its obscurity.

### Practical
-   Implement a global middleware in your framework that checks for a valid authentication token on every incoming request, unless a route is explicitly marked as public.
-   When designing a new feature, explicitly define the permissions required for each new endpoint. For example: "To call `GET /api/users/{id}`, the caller must be authenticated AND have the `users:read` scope OR be the user with the matching `id`."
-   Configure your API Gateway to set sensible default rate limits on all endpoints and tighter limits on sensitive or computationally expensive ones.

### Tools/Techniques
*   **API Gateways**: [Kong](https://konghq.com/), [Tyk](https://tyk.io/), [AWS API Gateway](https://aws.amazon.com/api-gateway/), [Apigee](https://cloud.google.com/apigee)
*   **Policy as Code**: [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) allows you to decouple and centralize authorization logic from your application code.
*   **Network Policies (Kubernetes)**: Use tools like [Calico](https://www.tigera.io/project-calico/) or [Cilium](https://cilium.io/) to enforce network-level segmentation, preventing a compromised service from accessing other internal services or databases it shouldn't.

### Metrics/Signal
*   Percentage of API endpoints covered by automated authorization tests in the CI/CD pipeline.
*   Number of alerts for rate-limiting violations from the API Gateway.

{% endblock %}
{% block type='battlecard' text='Expose' %}
### Explanation
To detect an attack in progress, you need to monitor for the signals of reconnaissance and exploitation. An attacker using these tools leaves a distinct trail.
-   **Reconnaissance Probing**: You'll see a series of requests for common paths (`/swagger-ui.html`, `/graphql`, etc.) from a single IP address, most of which will result in 404s. This is a strong indicator of a content discovery scan.
-   **Anomalous API Usage**: If an attacker successfully accesses a tool and an API, their behavior will differ from a normal user. This could be a sudden spike in requests to a single endpoint, unusually large response sizes (indicating data export), or queries that are far more complex than normal (e.g., deeply nested GraphQL queries).
-   **WAF/RASP Alerts**: A properly configured Web Application Firewall (WAF) or Runtime Application Self-Protection (RASP) tool can detect and block suspicious requests, such as GraphQL queries with disabled introspection or patterns that look like SQL injection.

### Insight
Effective detection isn't about looking for a single event; it's about correlating several weaker signals into a strong indicator of an attack. A single 404 is noise. A hundred 404s for common admin paths from one IP in 60 seconds is a signal. A 200 OK on `/graphql` from that same IP, followed by a 500-megabyte response from `/api/v1/users/export`, is an incident.

### Practical
-   **Create Log-Based Alerts**: In your logging platform (e.g., Splunk, Datadog), create a rule that alerts when a single source IP generates more than X 404 errors on paths containing "swagger", "graphql", "admin", etc., within a Y-minute window.
-   **Monitor Response Sizes**: Track the 95th and 99th percentile response sizes for your key API endpoints. Alert on any response that significantly exceeds this baseline.
-   **Monitor GraphQL Query Depth**: Log and monitor the depth and complexity of incoming GraphQL queries. A sudden increase in complexity can be a sign of an attacker attempting to over-fetch data.

### Tools/Techniques
*   **Log Management & SIEM**: [Elastic Stack](https://www.elastic.co/elastic-stack), [Splunk](https://www.splunk.com/), [Datadog](https://www.datadoghq.com/), [Graylog](https://www.graylog.org/)
*   **Web Application Firewall (WAF)**: [Cloudflare WAF](https://www.cloudflare.com/waf/), [AWS WAF](https://aws.amazon.com/waf/), [ModSecurity](https://modsecurity.org/)
*   **GraphQL Security**: [Inigo](https://inigo.io/), [WunderGraph](https://wundergraph.com/), [Apollo Server's complexity limiting](https://www.apollographql.com/docs/apollo-server/security/integration-testing/)

### Metrics/Signal
*   Number of alerts fired for "Path Discovery Scanning" from a single IP.
*   Anomaly detection alerts for API response sizes or request frequency.
*   GraphQL query complexity scores that exceed a predefined threshold.

{% endblock %}
{% block type='battlecard' text='eXercise' %}
### Explanation
Building "muscle memory" for security requires deliberate practice. The goal is to make finding and fixing these issues a routine part of the development process, not a panicked reaction to an incident.
1.  **Run Internal "Red Team" Drills**: Designate a security champion or a small group to periodically and ethically attack your own staging and UAT environments. Give them the same goal as an attacker: find exposed infrastructure and PII.
2.  **Tabletop Exercises**: Pose a realistic scenario to the team: "We've just received an alert that the Swagger UI on the `promotions-service-staging` environment is public. What's our playbook? Who do we notify? How do we validate the fix? How do we check other services?"
3.  **Integrate Security into the Workflow**: Make security checks a required part of your process. Add an automated DAST scan to your CI/CD pipeline that specifically looks for these endpoints on every new deployment to a test environment.

### Insight
The most effective exercises are the ones that test the *process*, not just the *technology*. It's great if a tool finds a vulnerability, but it's better to know that when the tool fires an alert, the on-call developer knows exactly what to do, who to contact, and how to deploy a fix safely and quickly. This builds confidence and reduces the real-world time-to-remediate.

### Practical
-   **Schedule a Bug Bash**: Once a quarter, hold a company-wide "bug bash" where developers are encouraged and rewarded for finding security vulnerabilities in pre-production environments. Focus one on exposed infrastructure.
-   **Use a Pre-Deployment Checklist**: Add a simple, mandatory checkbox to your pull request template or deployment tool: "I have verified that all debug/development endpoints (Swagger, GraphiQL, etc.) are disabled or secured in this build."
-   **Blameless Postmortems**: When a real (or practiced) incident occurs, conduct a blameless postmortem. The goal isn't to find who to blame, but to understand *why* the failure happened (e.g., "Our pipeline variables were confusing," or "The documentation for securing Swagger was unclear") and generate action items to fix the systemic cause.

### Tools/Techniques
*   **DAST Scanners**: [OWASP ZAP](https://www.zaproxy.org/), [Burp Suite Enterprise](https://portswigger.net/burp/enterprise) can be integrated into CI/CD pipelines.
*   **Security Champions Program**: A formal program to train and empower developers within teams to be the first line of defense and a local expert on security.
*   **Scenario Platforms**: [AttackIQ](https://attackiq.com/) (commercial) or custom scripts can be used to run automated, continuous validation of security controls.

### Metrics/Signal
*   Mean Time to Remediate (MTTR) for vulnerabilities of this class, measured from discovery to deployment of the fix.
*   Percentage of development teams that have participated in a security exercise (bug bash, tabletop) in the last six months.
*   Number of security-related action items generated from postmortems that are successfully completed.
{% endblock %}