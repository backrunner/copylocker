# CopyLocker Licensing

## Public Repository

Unless a file states otherwise, original source code and documentation in this repository are
licensed under the GNU General Public License version 3 only (`GPL-3.0-only`). The complete license
text is in [LICENSE](LICENSE).

Third-party dependencies, generated platform declarations, and vendored material remain under
their respective licenses. Their presence does not relicense them under the GPL.

## Private Repository

The proprietary `copylocker-suite-priv` implementation is not part of this public license. It is
maintained in a separate access-controlled repository under a commercial license. Authorized
checkouts may mount that repository at:

```text
private/copylocker-suite-priv
```

The actual submodule entry must not be added until the real private repository URL and access
policy are available. The public workspace, lockfiles, release artifacts, and CI must not require
the submodule.

## Combined Distribution

Repository separation, a Git submodule, a private registry, or a one-way Rust dependency does not
create a GPL linking exception. Before distributing a binary that combines GPL-covered CopyLocker
components with proprietary components, the distributor must use one of these approved models:

1. Obtain a separate commercial license for the relevant public components from their copyright
   holder.
2. Keep proprietary functionality in a legally and technically separate process or service, with
   the boundary reviewed before release.
3. Distribute the combined work in full compliance with the GPL, including corresponding-source
   obligations.

Internal-only or hosted use must still be reviewed against applicable law and customer contracts.
This repository policy is an engineering guardrail, not legal advice.

## Contributions

By contributing original work to this public repository, contributors agree that their
contribution is distributed under `GPL-3.0-only`. Contributors must have the right to submit the
work and must not copy proprietary private-repository content into the public history, issues,
tests, vectors, logs, or build artifacts.
