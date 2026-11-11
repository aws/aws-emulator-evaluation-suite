"""package-version-published-time-timestamp-precision-preserved."""
from __future__ import annotations

import hashlib
import time

from behavioral_harness import tags

CHECK = "package-version-published-time-timestamp-precision-preserved"
GROUP = "server-side"
SERVICES = ["codeartifact"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The publishedTime from PublishPackageVersion is returned with the same instant and microsecond
    precision on at least three later DescribePackageVersion calls."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-capubtime-")
    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))

    repo = ctx.unique_name("repo-")
    ca.create_repository(
        domain=domain, repository=repo, tags=[{"key": "sim2real", "value": CHECK}]
    )
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))

    namespace = "sim2real-ns"
    package = ctx.unique_name("timepkg-")
    version = "1.0.0"
    content = b"published-time-precision-check"
    sha = hashlib.sha256(content).hexdigest()

    ca.publish_package_version(
        domain=domain,
        repository=repo,
        format="generic",
        namespace=namespace,
        package=package,
        packageVersion=version,
        assetContent=content,
        assetName="asset.bin",
        assetSHA256=sha,
    )

    def _describe_published_time():
        return ca.describe_package_version(
            domain=domain,
            repository=repo,
            format="generic",
            namespace=namespace,
            package=package,
            packageVersion=version,
        )["packageVersion"]["publishedTime"]

    first = _describe_published_time()

    # Poll repeatedly across a bounded window, asserting the observable condition
    # (publishedTime is unchanged) on every observation, rather than sleeping once
    # and hoping. This both bounds worst-case runtime and catches a re-generated/
    # re-truncated timestamp at the earliest observation instead of only at the end.
    deadline = time.monotonic() + 20.0
    observations = 0
    while time.monotonic() < deadline:
        time.sleep(2.0)
        observed = _describe_published_time()
        assert observed == first, (
            f"publishedTime changed across describes: {first!r} != {observed!r}"
        )
        assert observed.microsecond == first.microsecond, (
            f"publishedTime precision drifted: {first.microsecond!r} != {observed.microsecond!r}"
        )
        observations += 1
    assert observations >= 3, "did not get enough repeated observations to trust stability"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
