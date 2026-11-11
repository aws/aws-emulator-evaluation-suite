"""list-package-versions-returns-newest-first."""
from __future__ import annotations

import hashlib
import time

from behavioral_harness import tags

CHECK = "list-package-versions-returns-newest-first"
GROUP = "ordering"
SERVICES = ["codeartifact"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListPackageVersions returns versions most-recently-published first,
    consistently even when paginated one item at a time."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-ca-")
    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))
    repo = ctx.unique_name("sim2real-behav-repo-")
    ca.create_repository(domain=domain, repository=repo,
                          tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))

    package = ctx.unique_name("sim2real-behav-pkg-")
    versions = ["1.0.0", "1.0.1", "1.0.2"]
    for version in versions:
        _publish_generic(ctx, domain, repo, package, version)
        # Ensure the publishedTime timestamps are distinguishable.
        time.sleep(1.5)

    # Walk the full list one item at a time to exercise pagination.
    observed = []
    next_token = None
    for _ in range(len(versions) + 2):
        kwargs = dict(
            domain=domain,
            repository=repo,
            format="generic",
            namespace="sim2real-behav-ns",
            package=package,
            sortBy="PUBLISHED_TIME",
            maxResults=1,
        )
        if next_token:
            kwargs["nextToken"] = next_token
        resp = ca.list_package_versions(**kwargs)
        observed.extend(v["version"] for v in resp["versions"])
        next_token = resp.get("nextToken")
        if not next_token:
            break

    expected_newest_first = list(reversed(versions))
    assert observed == expected_newest_first, (
        f"expected newest-first order {expected_newest_first}, got {observed}"
    )


def _publish_generic(ctx, domain: str, repository: str, package: str, version: str) -> None:
    ca = ctx.client("codeartifact")
    content = f"sim2real behavioral asset for {package}@{version}".encode()
    sha256 = hashlib.sha256(content).hexdigest()
    ca.publish_package_version(
        domain=domain,
        repository=repository,
        format="generic",
        namespace="sim2real-behav-ns",
        package=package,
        packageVersion=version,
        assetContent=content,
        assetName="asset.txt",
        assetSHA256=sha256,
    )



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
