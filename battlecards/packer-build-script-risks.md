---
title: Packer Build Script Risks
category: Infrastructure & Cloud
ref: RFX-INF-05
precedent: "2021"
scenario: Backdoor baked into a golden image by an unverified install script
focus:
  - unverified downloads in Packer provisioners
  - golden image poisoning across a fleet
  - image revocation and ancestry
---

## Scenario

A platform team builds a golden Ubuntu AMI with Packer every night. Every service in the company launches from it. The template installs a monitoring agent with a line copied from the vendor's quick-start guide:

```hcl
provisioner "shell" {
  inline = ["curl -sSL https://get.agent-vendor.example/install.sh | sudo bash"]
}
```

An attacker compromises the vendor's download server and edits `install.sh`. The agent still installs. The script also drops a small systemd service that beacons out every hour and adds an SSH key for a user called `svc-metrics`.

The next nightly build bakes all of that into the image. HCP Packer, or a simple "latest AMI" lookup in Terraform, promotes it. Over the following week, autoscaling groups and blue-green deploys roll every service onto the poisoned image. Rebuilding a single server fixes nothing, because the image *is* the infection.

::: {! precedent}
**Real-world precedent:** From January to April 2021, attackers modified [Codecov's Bash Uploader](https://about.codecov.io/security-update/), a script that thousands of pipelines fetched fresh and executed on every run. Any image build that pipes a vendor script into a shell has the same exposure, with the added problem that the result is copied to every machine you launch.
:::

::: {! stage recon}
## Reconnaissance

### Explanation

Attackers go after the places many image builds fetch from: vendor install scripts, agent download servers, GitHub release assets, and personal gists that a popular blog post recommended. A single compromise lands in every image built while it is live.

### Insight

A golden image multiplies whatever goes into it. One build-time fetch becomes thousands of running hosts, and the change hides among the hundreds of packages a base image legitimately installs.

### Practical

- List every network fetch in your Packer templates and the scripts they call: `curl`, `wget`, `apt-add-repository`, `pip install`, `npm install -g`, `git clone`.
- Note which of those are pinned to a version and verified against a hash or signature you control.
- Note whether any template is public. Public templates tell attackers exactly which vendors to target.

### Tools/Techniques

- `rg -n '(curl|wget)' --glob '*.pkr.hcl' --glob 'scripts/**'` to find fetches.
- `packer inspect` to list provisioners in a template.

### Metrics/Signal

- Number of unverified network fetches per template.
- Number of services launched from images built by those templates.
:::

::: {! stage evaluate}
## Evaluate

### Explanation

Check how each provisioner gets its software, what the builder instance can reach, and how a built image is promoted to production.

### Insight

Packer's `file` provisioner copies local files to the builder. It cannot fetch a URL or check a hash. Verification has to happen in a `shell` provisioner, or before Packer runs. Also check the base image: Ubuntu 20.04 left standard support in May 2025, so templates still pinned to it are building on an unpatched foundation.

### Practical

- Flag any provisioner that uses `http://` or pipes a download into a shell.
- Check the `source_ami_filter`: it should pin the publisher's account ID, not only a name pattern anyone could copy.
- Check whether built images go straight to production or through a channel or tag that someone promotes after tests.
- Check which variables are secrets, and whether they are marked `sensitive = true` so Packer masks them in logs.

### Tools/Techniques

- `packer validate` and `packer fmt -check` in CI.
- [Trivy](https://trivy.dev/) misconfiguration scanning for the surrounding Terraform that consumes the image.

### Metrics/Signal

- Templates on base images past their standard support date.
- Images promoted to production without an automated test gate.
:::

::: {! stage fortify}
## Fortify

### Explanation

Pin versions and hashes, fetch over HTTPS only, use signed package repositories where they exist, and promote images deliberately.

### Insight

When the expected hash lives in your template, a tampered download fails the build. That is the outcome you want: a red nightly build instead of a green, poisoned image.

### Practical

- Pin the base image to the publisher's account and a supported release:

    ```hcl
    source "amazon-ebs" "base" {
      region        = "eu-west-2"
      instance_type = "t3.small"
      ssh_username  = "ubuntu"
      ami_name      = "app-base-${formatdate("YYYYMMDDhhmm", timestamp())}"

      source_ami_filter {
        filters = {
          name                = "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"
          virtualization-type = "hvm"
        }
        owners      = ["099720109477"] # Canonical
        most_recent = true
      }
    }
    ```

- Download, verify, then install:

    ```hcl
    locals {
      agent_version = "2.8.1"
      agent_sha256  = "<sha256 from the vendor's signed release notes>"
    }

    build {
      sources = ["source.amazon-ebs.base"]

      provisioner "shell" {
        inline = [
          "curl -fsSLo /tmp/agent.deb https://downloads.agent-vendor.example/agent_${local.agent_version}_amd64.deb",
          "echo '${local.agent_sha256}  /tmp/agent.deb' | sha256sum -c -",
          "sudo apt-get install -y /tmp/agent.deb",
          "rm /tmp/agent.deb",
        ]
      }
    }
    ```

- If the vendor runs a signed apt repository, use it with a pinned key file (`signed-by=`) and a pinned package version instead of a script.
- Register builds in [HCP Packer](https://developer.hashicorp.com/hcp/docs/packer) and have Terraform consume a named channel (for example `production`) rather than "latest". Promote to that channel only after tests pass.

### Tools/Techniques

- `sha256sum -c`, signed apt repositories, [cosign](https://docs.sigstore.dev/) for vendor artefacts that ship Sigstore bundles.
- HCP Packer channels and the `hcp_packer_registry` block.

### Metrics/Signal

- Percentage of fetches with a pinned hash or signature check.
- Percentage of production launches that resolve images through a promoted channel.
:::

::: {! stage limit}
## Limit

### Explanation

Keep the builder from leaking credentials, and make a bad image quick to pull from circulation.

### Insight

The worst version of this attack is one you cannot undo quickly. Revocation and ancestry tracking in HCP Packer turn "which images contain the bad agent?" from an archaeology project into a query.

### Practical

- Give the temporary builder instance no IAM role, or one scoped to what provisioning needs. Never reuse a production role.
- Restrict builder egress to your package mirrors and named vendor hosts.
- Use HCP Packer [revocation](https://developer.hashicorp.com/hcp/docs/packer/manage/revoke-restore) to block a bad version, roll channels back, and optionally revoke descendant images built on top of it.
- Keep runtime hardening in the image: no shared SSH keys, unexpected users locked, outbound traffic from hosts limited by security groups.

### Tools/Techniques

- HCP Packer revocation, channel rollback and ancestry.
- Security groups or VPC egress controls on the build subnet.

### Metrics/Signal

- Time to revoke an image and roll back its channel.
- Builders running with production IAM roles (should be zero).
:::

::: {! stage expose}
## Expose

### Explanation

Inspect what each image contains before it ships, and compare it with the previous build.

### Insight

A backdoored agent install changes a few things you can see: a new systemd unit, a new user, a new `authorized_keys` entry, a new listening port. Diffing image to image makes these stand out.

### Practical

- Generate an SBOM inside the build and pull it back with the `file` provisioner:

    ```hcl
    provisioner "shell" {
      inline = ["sudo syft dir:/ --exclude './proc/**' --exclude './sys/**' -o spdx-json > /tmp/sbom.json"]
    }

    provisioner "file" {
      direction   = "download"
      source      = "/tmp/sbom.json"
      destination = "build/sbom.json"
    }
    ```

- Run server tests against the builder before the image is saved: expected users, expected systemd units, no unexpected `authorized_keys` entries.
- Diff the SBOM, user list and enabled units against the previous image. Alert on additions nobody asked for.
- Alert on hosts making outbound connections to destinations outside your allow list.

### Tools/Techniques

- [Syft](https://github.com/anchore/syft) for SBOMs and [Grype](https://github.com/anchore/grype) or Trivy to scan them.
- [Goss](https://github.com/goss-org/goss) for fast server validation tests.
- VPC flow logs for unexpected egress.

### Metrics/Signal

- Unexplained additions per image diff.
- Images saved without passing validation tests (should be zero).
:::

::: {! stage exercise}
## Exercise

### Explanation

Check that a tampered download fails the build and that you can revoke an image quickly.

### Insight

Both drills fit in an afternoon in a sandbox account.

### Practical

1. Host a harmless `.deb` or tarball in a sandbox S3 bucket. Pin its SHA-256 in a test template.
2. Replace the file with a modified one. Run `packer build` and confirm the `sha256sum -c` step fails the build.
3. Build a test image that adds a dummy systemd unit. Confirm your Goss tests or image diff flag it.
4. Register the test image in HCP Packer, assign it to a channel, then revoke it. Time how long it takes for Terraform plans in a sandbox workspace to stop resolving it.

### Tools/Techniques

- A sandbox cloud account and a test HCP Packer bucket.
- Goss and Syft from the Expose stage.

### Metrics/Signal

- Whether the tampered build failed.
- Minutes from revocation to the channel no longer serving the image.
:::

## Further Reading

- [Codecov security update (April 2021)](https://about.codecov.io/security-update/)
- [Packer shell provisioner](https://developer.hashicorp.com/packer/docs/provisioners/shell)
- [HCP Packer: revoke and restore artifact versions](https://developer.hashicorp.com/hcp/docs/packer/manage/revoke-restore)
- [HCP Packer: channels](https://developer.hashicorp.com/hcp/docs/packer/manage/channel)
