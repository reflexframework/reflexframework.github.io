---
---
# REFLEX Security Review — D&D Character Generator (Quarkus + Vaadin + LLM)

This document captures the current security posture of the application using the **REFLEX methodology**:  
**Reconnaissance → Evaluate → Fortify → Limit → Expose → eXecute**

---

## Reconnaissance
- [ ] **Architecture map**: Document user flow → Vaadin UI → Quarkus REST → LLM/text+image → storage.
- [ ] **Data inventory**: List all user data stored (profiles, chat logs, images, embeddings). Note retention & classification (PII / non-PII).
- [ ] **Tenant model**: How is user isolation enforced? (`tenant_id` field, RLS, per-schema).
- [ ] **LLM topology**: Which providers are used (text + image)? What tools/functions/agents are enabled?
- [ ] **AuthN/Z**: Which IdP (Keycloak/Auth0/etc.)? Which roles/claims are supported? Where are checks enforced?
- [ ] **Secrets**: Where are LLM keys and storage creds kept (Vault/KMS)? What’s the rotation cadence?
- [ ] **Build chain**: CI/CD pipeline overview (Vaadin assets, Quarkus builds, containerization). SBOMs produced? SCA tools?

---

## Evaluate 

Where are we weakest? What’s exposed?

- [ ] **IDOR checks**: Can a user access another’s character by ID?
- [ ] **Server-side authorization**: Point to the central place ownership checks are enforced.
- [ ] **Input constraints**: Max prompt size, allowed content, Markdown/HTML safety policy, upload limits.
- [ ] **LLM guardrails**: What system prompts, jailbreak filters, or output validators exist?
- [ ] **Storage access**: Are presigned URLs random, short-lived, single-use, and private?
- [ ] **Rate limiting & quotas**: Are there per-user/IP/token budgets? Separate limits for images vs text?
- [ ] **Observability**: Can we trace requests end-to-end per tenant (LLM spend, errors, token counts)?

---

## Fortify 

What should we harden now?

- [ ] **DB isolation**: Postgres Row-Level Security enabled with `tenant_id`.
- [ ] **Centralized authZ**: All ownership checks handled in Quarkus interceptors / security filters.
- [ ] **Output encoding**: Encode/escape all user text. Sanitize Markdown/HTML (disallow dangerous tags/SVG).
- [ ] **Upload pipeline**: Virus scan, strip EXIF, size limits, rasterize SVGs.
- [ ] **Secrets mgmt**: All keys in Vault/KMS, short TTL, no plaintext in logs/config.
- [ ] **LLM policies**: Explicit allow-list for tools/URLs. Post-processing filters. Abuse keyword detection.
- [ ] **Egress**: Only to LLM endpoints. Block all other outbound unless allow-listed.

---

## Limit 

Blast radius & abuse control

- [ ] **Scopes & roles**: Least-privilege roles, minimal JWT claims.
- [ ] **Quotas**: Daily per-user token/image caps, cost guardrails.
- [ ] **Presigned URL TTLs**: ≤5 minutes, single-use.
- [ ] **Resource ceilings**: CPU/mem limits per pod. Circuit breakers for model calls.
- [ ] **Feature flags**: Risky features (agents/external fetch) toggled per environment.

---

## Expose 

Detect, observe, and prove

- [ ] **Audit trails**: Who created/edited/deleted which character? Linked to auth subject & IP.
- [ ] **Security logs**: IDOR attempts, rate-limit hits, LLM jailbreak attempts.
- [ ] **Per-tenant dashboards**: Usage stats, spend, abuse detection.
- [ ] **Tamper-evident logs**: Signed/hash-verified audit logs, stored in WORM or append-only medium.

---

## eXecute 

Runbooks, tests, drills

- [ ] **Abuse runbooks**: Document steps for IDOR, mass-gen abuse, key leak, NSFW outbreak.
- [ ] **Red-team/chaos tests**: Automated IDOR tests, prompt-injection fuzzing, ACL break attempts.
- [ ] **Supply chain gates**: SBOMs in CI/CD, block builds on KEV/CISA high-risk CVEs.
- [ ] **Key compromise drill**: Rotate LLM keys, block traffic, notify tenants. Verify observability catches the spike.
- [ ] **Incident response**: Who is on call? What SLA? What’s the escalation chain?

---

## Quick Health Checklist 

- [ ] DB RLS enforced
- [ ] AuthZ checks tested (happy + evil paths)
- [ ] User text always escaped/sanitized
- [ ] Presigned URLs private + short-lived
- [ ] LLM keys vaulted & rotated
- [ ] Per-tenant quotas enforced
- [ ] Prompt-injection tests in CI
- [ ] SBOM + SCA gates in pipeline
- [ ] Per-tenant dashboards live
- [ ] Runbooks rehearsed  
