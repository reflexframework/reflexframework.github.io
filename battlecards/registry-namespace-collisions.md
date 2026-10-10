---
title: Registry Namespace Collisions
category: Package Ecosystems
scenario: Attacker claims your organisation's name on public registries
focus:
  - unclaimed npm scopes and Docker Hub namespaces
  - short names that default to public registries
  - abandoned GitHub organisation names after a rename
---

## Scenario

Acme names everything `acme`. Internal npm packages live under `@acme/` in Artifactory. Base images live at `registry.acme.internal/acme/python-base`. The GitHub organisation was renamed from `acme-labs` to `acme` last year. Nobody ever claimed `acme` on npmjs.com or Docker Hub, and nobody kept `acme-labs` on GitHub.

An attacker checks each registry for the name and finds three gaps.

1. **npm.** They create the `acme` organisation on npmjs.com and publish `@acme/logger`. A contractor clones a repository without the team's `.npmrc`. npm sends the `@acme` scope to the public registry, and the attacker's package installs.
2. **Docker Hub.** They register the `acme` namespace and push `acme/python-base:3.12`. A Helm chart and two Dockerfiles use the short name `acme/python-base`. Short names resolve to Docker Hub, so those builds pull the attacker's image.
3. **GitHub.** They register the free `acme-labs` organisation and create `acme-labs/setup-acme-cli`. Workflows still reference `uses: acme-labs/setup-acme-cli@v2`. GitHub does not redirect actions after a rename, so they now run the attacker's code with the workflow's token.

This card is about owning your name across every registry. For the resolution-order bug where a public package beats an internal one of the same name, see [Dependency Confusion Attacks](#battlecards-dependency-confusion-attacks-md).

**Real-world precedent:** In May 2022 an attacker re-registered `hautelook`, a GitHub account closed in 2021, recreated the `phpass` repository and pushed versions that stole AWS credentials. Packagist pulls PHP packages straight from source control, so the reclaimed name fed directly into installs of a package with over 2.5 million downloads ([Checkmarx](https://checkmarx.com/blog/attacker-caught-hijacking-packages-using-multiple-techniques-to-steal-aws-credentials/), [BleepingComputer](https://www.bleepingcomputer.com/news/security/popular-pypi-and-php-libraries-hijacked-to-steal-aws-keys/)).

::: {! stage recon}
## Reconnaissance

### Explanation
The attacker builds a list of names your organisation uses: npm scopes, Docker namespaces, GitHub organisations (current and former), Maven `groupId`s and PyPI prefixes. Then they check which of those names are unclaimed on each public registry.

### Insight
Every registry has its own namespace, and claiming a name on one claims nothing on the others. An organisation rename doubles the list, because the old name is free the moment you let it go.

### Practical
- List every name your organisation uses, including former names, product names and the prefixes on internal packages.
- Check each one against each public registry. The npm endpoint returns 404 if no user or organisation owns the scope.

```bash
for name in acme acme-labs; do
  echo "$name npm:$(curl -s -o /dev/null -w '%{http_code}' https://registry.npmjs.org/-/org/$name/package)"
  echo "$name dockerhub:$(curl -s -o /dev/null -w '%{http_code}' -L https://hub.docker.com/v2/users/$name/)"
  echo "$name github:$(curl -s -o /dev/null -w '%{http_code}' https://api.github.com/users/$name)"
done
```

- Search your code for short image names, unscoped internal packages and `uses:` lines that point at former organisation names.

### Tools/Techniques
- Registry APIs as above, run as a scheduled job.
- GitHub code search, for example `org:acme "uses: acme-labs/"` or `org:acme "FROM acme/"`.
- [confused](https://github.com/visma-prodsec/confused): note that it can't see npm scope ownership, so check scopes directly.

### Metrics/Signal
- Count of your names that are unclaimed on each registry.
- Count of references to former organisation names.
:::

::: {! stage evaluate}
## Evaluate

### Explanation
For each unclaimed name, ask what would happen if an attacker took it tomorrow. A name is dangerous when some client, somewhere, would resolve it to the public registry.

### Insight
The risky clients are rarely the main CI pipeline. They are contractor laptops, a forgotten build server, a Helm chart someone copied, or a workflow in a repository nobody has touched since the rename.

### Practical
- npm: run `npm config get @acme:registry` on a fresh machine with no dotfiles. If it prints `undefined`, the scope goes to npmjs.com.
- Containers: find image references with no registry host. Docker treats `acme/python-base` as `docker.io/acme/python-base`.

```bash
grep -rnE '^\s*FROM\s+[a-z0-9-]+/[^ ]+' --include='Dockerfile*' .
grep -rnE 'image:\s*"?[a-z0-9-]+/[^ ]+' --include='*.yaml' .
```

- GitHub and Packagist: list every `uses:` reference, and every Composer or Go module path, that points at an owner you don't control today.
- Maven: confirm each `groupId` you publish is verified on Maven Central. Unowned groupIds are covered in [Dependency Confusion Attacks](#battlecards-dependency-confusion-attacks-md).

### Tools/Techniques
- `npm config`, `grep`, and GitHub code search.
- [Maven Central namespace registration](https://central.sonatype.org/register/namespace/).

### Metrics/Signal
- Unqualified image references in Dockerfiles and charts.
- Workflows referencing actions under a former or unowned owner.
:::

::: {! stage fortify}
## Fortify

### Explanation
Claim your names everywhere they could be used, and stop relying on defaults that point at public registries.

### Insight
Claim names in ways each registry's policy allows. On PyPI, an empty placeholder package counts as name squatting under PEP 541 and can be removed. Use the registry's organisation features instead.

### Practical
- **npm:** create the `acme` organisation on npmjs.com, even if you never publish publicly. Then nobody else can publish under `@acme`. Route the scope in a committed `.npmrc` as well.

```ini
@acme:registry=https://npm.acme.internal/
```

- **PyPI:** create a [PyPI Organization](https://blog.pypi.org/posts/2023-04-23-introducing-pypi-organizations/) for the projects you publish. An organisation owns its projects, but it does not reserve a prefix like `acme-`. PEP 752, accepted in June 2026, defines prefix reservations. Check whether PyPI has enabled them before relying on it.
- **Docker Hub:** create the `acme` organisation. Always write fully qualified image references, such as `registry.acme.internal/acme/python-base:3.12`, ideally pinned by digest.
- **GitHub:** when you rename an organisation, keep the old name by creating a new, empty organisation with it. GitHub only retires `old-owner/repo` names for popular repositories and actions, so don't count on that. Update every `uses:` line, and pin actions to full commit SHAs.
- **Maven:** verify the namespace behind every `groupId` you use on Maven Central, as described in [Dependency Confusion Attacks](#battlecards-dependency-confusion-attacks-md).

### Tools/Techniques
- [npm organisations](https://docs.npmjs.com/creating-an-organization) and [scopes](https://docs.npmjs.com/about-scopes).
- [PEP 752: Implicit namespaces for package repositories](https://peps.python.org/pep-0752/).
- [GitHub: Renaming an organisation](https://docs.github.com/en/organizations/managing-organization-settings/renaming-an-organization).
- Podman and Buildah `registries.conf` with `short-name-mode = "enforcing"` to stop silent resolution of short names.

### Metrics/Signal
- Your core names are claimed on npm, Docker Hub, GitHub and PyPI.
- Zero unqualified image references.
:::

::: {! stage limit}
## Limit

### Explanation
If an attacker's package, image or action runs, its reach depends on where it runs. A squatted action runs inside your workflow. A squatted image may become your production base.

### Insight
A hijacked action is the worst of the three. It runs with whatever `GITHUB_TOKEN` permissions and secrets the job has.

### Practical
- Set `permissions:` to read-only by default in every workflow, and grant write scopes per job.
- Use an organisation-level allowlist of actions, so a workflow can't call an action from an unknown owner.
- Restrict which registries your clusters can pull from with an admission policy, so a Docker Hub look-alike can't run.
- For install-time controls on a squatted npm package, see the Limit stage of [Dependency Confusion Attacks](#battlecards-dependency-confusion-attacks-md).

### Tools/Techniques
- GitHub "Allow specified actions and reusable workflows" organisation setting.
- [Kyverno](https://kyverno.io/) or OPA Gatekeeper policies that only admit images from your registry.

### Metrics/Signal
- Workflows with default read-only permissions.
- Pods rejected for using a non-approved registry.
:::

::: {! stage expose}
## Expose

### Explanation
You want to know the moment someone claims one of your names, and the moment one of your builds pulls from a namespace you don't own.

### Insight
Name registrations are public. You can watch them as easily as an attacker can.

### Practical
- Run the Recon script on a schedule and alert when a name changes from 404 to claimed by someone else.
- Log image pulls and alert on any `docker.io/acme/*` pull, since you publish nothing there.
- Alert on workflow runs that download an action from an owner outside your allowlist.
- Repository manager alerts for internal names reaching a public remote are covered in [Dependency Confusion Attacks](#battlecards-dependency-confusion-attacks-md).

### Tools/Techniques
- Scheduled CI job using registry APIs.
- Container registry and cluster audit logs.
- GitHub audit log streaming for workflow and action events.

### Metrics/Signal
- New public registrations of your names by unknown accounts.
- Any pull of an image from a namespace you don't control.
:::

::: {! stage exercise}
## Exercise

### Explanation
Rehearse a scope takeover with local registries. Never publish test packages to public registries: it breaks their policies and pollutes the ecosystem.

### Insight
The point of the drill is the unconfigured machine. Your CI may be fine while a new starter's laptop is not.

### Practical
1. Run two [Verdaccio](https://verdaccio.org/) instances: "internal" and "public". Treat "public" as the default registry, as npmjs.com would be.
2. Publish `@acme/logger` `1.0.0` to "internal" and `@acme/logger` `1.0.1` to "public", whose install script only resolves a DNS canary token.
3. On a clean container with no `.npmrc`, set the default registry to "public" and install `@acme/logger`. Note which version arrives.
4. Add the committed `.npmrc` and repeat. You should get the internal package.
5. Run the Dockerfile and workflow `grep` checks from Evaluate across your repositories, and fix what they find.

### Tools/Techniques
- [Verdaccio](https://verdaccio.org/) for both registries.
- [Canarytokens](https://canarytokens.org/) for the benign payload.

### Metrics/Signal
- Clean machines with the committed `.npmrc` resolve `@acme` internally.
- Unqualified references found and fixed per repository.
:::

## Further Reading

- [Checkmarx: Attacker caught hijacking packages to steal AWS credentials (phpass, 2022)](https://checkmarx.com/blog/attacker-caught-hijacking-packages-using-multiple-techniques-to-steal-aws-credentials/)
- [PEP 752: Implicit namespaces for package repositories](https://peps.python.org/pep-0752/)
- [PyPI: Introducing PyPI Organizations](https://blog.pypi.org/posts/2023-04-23-introducing-pypi-organizations/)
- [PEP 541: Package Index Name Retention](https://peps.python.org/pep-0541/)
- [GitHub: Renaming an organisation](https://docs.github.com/en/organizations/managing-organization-settings/renaming-an-organization)
- Related card: [Dependency Confusion Attacks](#battlecards-dependency-confusion-attacks-md)
