---
title: Exposed Developer Consoles and Debug Endpoints
category: Infrastructure & Cloud
scenario: Internet-reachable Swagger UI, GraphQL explorers, Actuator, Jupyter, Jenkins and debug ports
focus:
  - Spring Boot Actuator heapdump and env
  - Swagger UI and GraphQL introspection
  - Jupyter and Jenkins script console
  - remote debug ports (JDWP, Node inspector)
---

## Scenario

An attacker enumerates subdomains for a fintech company and finds `dev-api.example-fintech.com`. A content scanner gets hits on `/swagger-ui/index.html`, `/graphql` and `/actuator`.

1. Swagger UI lists every endpoint, including an internal `POST /api/v1/users/search`.
2. The GraphQL endpoint answers an introspection query and reveals an `allUsers` field nobody meant to expose.
3. `/actuator/heapdump` is open. The attacker downloads a few hundred megabytes of JVM memory and searches it for strings. It contains the database password and a set of AWS access keys that the application loaded at start-up.

The "dev" environment shared a database snapshot and an IAM role with staging. The attacker now has real customer data and a foothold in the cloud account.

**Real-world precedent:** In December 2024 the Chaos Computer Club showed that a publicly reachable Spring Boot Actuator heap dump at Volkswagen's software company Cariad contained plaintext AWS credentials, exposing data on around 800,000 electric vehicles ([Wiz incident summary](https://threats.wiz.io/all-incidents/volkswagen-data-leak-through-spring-boot-actuator-misconfiguration), [The Register](https://www.theregister.com/2025/01/06/volkswagen_ev_data_exposed/)). In 2023 the [Qubitstrike campaign](https://www.darktrace.com/blog/qubitstrike-an-emerging-malware-campaign-targeting-jupyter-notebooks) used exposed Jupyter notebooks to steal cloud credentials and mine crypto.

::: {! stage recon}
## Reconnaissance

### Explanation

Attackers find these tools in bulk. They enumerate subdomains from certificate transparency logs, then probe each host for well-known paths:

- `/swagger-ui/index.html`, `/swagger-ui.html`, `/v3/api-docs`
- `/graphql`, `/graphiql`
- `/actuator`, `/actuator/env`, `/actuator/heapdump`
- `/script` (Jenkins), `/api` and `/tree` (Jupyter)

They also scan for open debug ports: JDWP on 5005 and the Node.js inspector on 9229. Internet-wide search engines such as Shodan and Censys index many of these already.

### Insight

These tools are meant for developers on a trusted network. Each one either documents your attack surface, leaks secrets, or runs code on request. A Jenkins script console, an unauthenticated Jupyter server or an open JDWP port is remote code execution by design.

### Practical

Survey your own estate the way an attacker would, from outside your network:

```bash
subfinder -d example-fintech.com -silent > hosts.txt
httpx -l hosts.txt -silent -path /actuator,/v3/api-docs,/graphql,/script,/api \
    -status-code -title
nmap -Pn -p 5005,8000,8888,9229 -iL hosts.txt --open
```

Only scan domains and addresses you own or have written permission to test.

### Tools/Techniques

- [subfinder](https://github.com/projectdiscovery/subfinder) and [httpx](https://github.com/projectdiscovery/httpx) for discovery.
- [nuclei](https://github.com/projectdiscovery/nuclei) templates for exposed Actuator, Swagger, Jupyter and Jenkins panels.
- Shodan or Censys searches for your organisation's IP ranges.

### Metrics/Signal

- Number of internet-reachable hosts serving any of the paths above.
- Open debug ports on internet-facing addresses (target: zero).
:::

::: {! stage evaluate}
## Evaluate

### Explanation

For each tool you find, ask: who can reach it, does it need authentication, and what can someone do with it?

### Insight

The risk varies a lot by tool:

- **Swagger UI and `/v3/api-docs`:** a map of your API. Bad when it reveals internal or unauthenticated endpoints.
- **GraphQL introspection:** the full schema, including fields you forgot to protect.
- **Actuator `/heapdump` and `/env`:** secrets. A heap dump contains everything in memory, including credentials that `/env` would mask.
- **Jenkins script console:** arbitrary Groovy on the controller, with access to every stored credential.
- **Jupyter:** a terminal and code execution as the server's user.
- **JDWP and Node inspector:** run any code in the process.

### Practical

1. Check which Actuator endpoints are exposed: `curl -s https://host/actuator | jq '._links | keys'`.
2. Check whether GraphQL introspection is on: send `{"query":"{ __schema { types { name } } }"}`.
3. Check Spring profiles and environment variables in deployment manifests for `springdoc` and `management.endpoints` settings.
4. Check how debug flags reach your containers: `JAVA_TOOL_OPTIONS` with `-agentlib:jdwp`, or `node --inspect=0.0.0.0`.

### Tools/Techniques

- `curl` and `jq`.
- [graphql-cop](https://github.com/dolevf/graphql-cop) for GraphQL misconfiguration checks.
- `kubectl get svc -A` to find services of type `LoadBalancer` or `NodePort` that expose debug or admin ports.

### Metrics/Signal

- Exposed endpoints classified by impact (documentation, secrets, code execution).
- Environments where "dev" shares data or credentials with staging or production.
:::

::: {! stage fortify}
## Fortify

### Explanation

Turn these tools off where they are not needed, and put authentication and network controls in front of them where they are.

### Insight

Configuration that differs by environment is easy to get wrong. Default to "off" in every profile and switch tools on only in local development.

### Practical

**Spring Boot (springdoc v2, Spring Security 6).** The v2 artifact is `springdoc-openapi-starter-webmvc-ui`. Disable the UI and docs outside local development:

```properties
# application-prod.properties (and staging, and shared dev)
springdoc.swagger-ui.enabled=false
springdoc.api-docs.enabled=false
management.endpoints.web.exposure.include=health
management.server.port=8081
management.server.address=127.0.0.1
```

Spring Boot exposes only `health` over HTTP by default. Keep it that way, and never add `heapdump` or `env` to the exposure list on anything reachable from outside. A separate management port bound to localhost keeps Actuator off the public listener.

If an environment must keep the docs, protect them with a `SecurityFilterChain` bean. `WebSecurityConfigurerAdapter` and `antMatchers` were removed in Spring Security 6.

```java
@Configuration
@EnableWebSecurity
class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/swagger-ui/**", "/v3/api-docs/**").hasRole("API_DOCS")
                .requestMatchers("/actuator/health").permitAll()
                .anyRequest().authenticated())
            .oauth2ResourceServer(oauth -> oauth.jwt(Customizer.withDefaults()));
        return http.build();
    }
}
```

Credentials come from your identity provider. Do not hardcode a password in the class or in `application.properties`.

**GraphQL (Apollo Server).** The `apollo-server` package (v3) is end-of-life, and so is Apollo Server 4. Use `@apollo/server` v5. It disables introspection when `NODE_ENV=production`; set it explicitly so a missing variable cannot turn it back on:

```javascript
import { ApolloServer } from '@apollo/server';

const server = new ApolloServer({
    typeDefs,
    resolvers,
    introspection: process.env.ENABLE_INTROSPECTION === 'true',
});
```

Add query depth and [complexity limits](https://github.com/slicknode/graphql-query-complexity) as well, so a public endpoint cannot be used for denial of service.

**Other tools.**

- Jupyter: keep token or password authentication on, bind to `127.0.0.1`, and reach it over SSH or a VPN. Never start it with an empty token on `0.0.0.0`.
- Jenkins: never expose the controller to the internet, enforce authentication with matrix-based or role-based authorisation, and give `Overall/Administer` (which grants the script console) to as few people as possible.
- JDWP: on JDK 9 and later, `address=5005` binds to localhost only. Never use `address=*:5005` in a shared or deployed image.
- Node: `--inspect` binds to `127.0.0.1:9229` by default. Never ship `--inspect=0.0.0.0` in a container image.

### Tools/Techniques

- Spring profiles and `SecurityFilterChain`.
- `@apollo/server` v5 with explicit `introspection`.
- An identity-aware proxy (Cloudflare Access, Google IAP, oauth2-proxy) in front of any internal tool that must be reachable remotely.

### Metrics/Signal

- Deployed environments with Swagger UI, introspection or non-health Actuator endpoints enabled.
- Container images containing debug flags.
:::

::: {! stage limit}
## Limit

### Explanation

If someone does reach a dev tool, make sure the environment behind it holds nothing worth stealing.

### Insight

In the Cariad case the real damage came from the cloud credentials held in memory. A dev environment with synthetic data and its own narrowly scoped role would have leaked very little.

### Practical

- Give each environment its own cloud account or project and its own IAM role. Dev must not be able to read staging or production data.
- Use synthetic or masked data in dev and test. Never restore a production snapshot to an internet-reachable environment.
- Use workload identity (IRSA, GKE Workload Identity, Azure workload identity) instead of static keys, so credentials in memory are short-lived.
- Put non-production environments behind a VPN or identity-aware proxy by default.

### Tools/Techniques

- Separate AWS accounts, GCP projects or Azure subscriptions per environment.
- Workload identity for pods and functions.
- Data masking in your database refresh pipeline.

### Metrics/Signal

- Non-production environments with access to production data or credentials (target: zero).
- Static cloud keys present in application environments.
:::

::: {! stage expose}
## Expose

### Explanation

Detect probing and access to these paths, and catch exposure before attackers do.

### Insight

Scanners hit `/actuator/heapdump` and `/v3/api-docs` constantly. A successful `200` response to one of them from the internet should page someone.

### Practical

- Alert on `200` responses for `/actuator/heapdump`, `/actuator/env`, `/script`, `/v3/api-docs` and GraphQL introspection queries from outside your network.
- Run your own external scan (the Reconnaissance commands above, or nuclei) on a schedule and fail a check when anything new appears.
- Add a deployment test that requests these paths against each environment and expects `401`, `403` or `404`.

```bash
for path in /actuator/heapdump /actuator/env /v3/api-docs /swagger-ui/index.html; do
    code=$(curl -s -o /dev/null -w '%{http_code}' "https://$HOST$path")
    if [ "$code" = "200" ]; then
        echo "EXPOSED: $HOST$path" >&2
        exit 1
    fi
done
```

### Tools/Techniques

- Load balancer or WAF access logs with alerts on these paths.
- nuclei in a scheduled CI job.
- External attack surface monitoring from your cloud provider or a third party.

### Metrics/Signal

- Successful responses to sensitive paths from external IPs.
- Time from a new exposure appearing to it being closed.
:::

::: {! stage exercise}
## Exercise

### Explanation

Rehearse the attacker's path against a deliberately exposed service you control.

### Insight

Seeing a password appear from `strings heapdump | grep` is far more convincing than any slide.

### Practical

1. In an isolated local environment, run a Spring Boot app with `management.endpoints.web.exposure.include=*` and a fake secret such as `CANARY_DB_PASSWORD=not-a-real-password`.
2. Download `/actuator/heapdump` and find the canary string with `strings heapdump | grep CANARY`.
3. Apply the Fortify settings and confirm the endpoint now returns `404` or `401`.
4. Run the deployment test from Expose against each real environment and fix anything it flags.

### Tools/Techniques

- A local Spring Boot app in Docker on a private network.
- Canary values only, never real secrets.

### Metrics/Signal

- Whether the deployment test passes in every environment.
- Number of exposures found by your own scans before anyone else reported them.
:::

## Further Reading

- [Spring Boot: Actuator endpoints and exposure](https://docs.spring.io/spring-boot/reference/actuator/endpoints.html)
- [springdoc-openapi features and properties](https://springdoc.org/features.html)
- [Apollo Server: previous versions and end-of-life dates](https://www.apollographql.com/docs/apollo-server/previous-versions)
- [Wiz: Volkswagen data leak through Spring Boot Actuator](https://threats.wiz.io/all-incidents/volkswagen-data-leak-through-spring-boot-actuator-misconfiguration)
- [Darktrace (Cado): Qubitstrike targets Jupyter notebooks](https://www.darktrace.com/blog/qubitstrike-an-emerging-malware-campaign-targeting-jupyter-notebooks)
