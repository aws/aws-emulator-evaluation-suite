"""update-status-to-disposed-rejected."""
from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-status-to-disposed-rejected"
GROUP = 'package-version-status-rejected'
SERVICES = ['codeartifact']


def _error(fn):
    """Call fn(); return (code, message). An unexpected SUCCESS is a hard failure."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        "the call SUCCEEDED where real AWS rejects it — there is no error code to compare"
    )


def _delete_domain(ca, domain, deadline=90.0):
    end = time.time() + deadline
    while True:
        try:
            ca.delete_domain(domain=domain)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException" or time.time() >= end:
                raise
            time.sleep(3)


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdatePackageVersionsStatus with targetStatus Disposed is refused with ValidationException "Target
    status is not allowed." and leaves the version Published, while DisposePackageVersions disposes it."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-ca-dom-")
    repo = ctx.unique_name("sim2real-behav-ca-repo-")
    package = "sim2real-dispose-route"
    content = b"dispose-route-payload\n"
    scope = dict(format="generic", namespace="sim2real", package=package)

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))
    ca.create_repository(domain=domain, repository=repo, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))

    ca.publish_package_version(
        domain=domain, repository=repo, packageVersion="1.0.0", assetContent=content,
        assetName="payload.bin", assetSHA256=hashlib.sha256(content).hexdigest(), **scope)
    ctx.on_cleanup(lambda: ca.delete_package(domain=domain, repository=repo, **scope))

    code, message = _error(lambda: ca.update_package_versions_status(
        domain=domain, repository=repo, versions=["1.0.0"], targetStatus="Disposed", **scope))
    assert code == "ValidationException", (
        f"targetStatus=Disposed returned {code!r}, expected ValidationException"
    )
    assert message == "Target status is not allowed.", (
        f"the refusal said {message!r}, expected 'Target status is not allowed.'"
    )

    still = ca.describe_package_version(
        domain=domain, repository=repo, packageVersion="1.0.0", **scope)["packageVersion"]
    assert still["status"] == "Published", (
        f"the refused transition left the version at {still['status']!r}, expected Published — a "
        f"rejection must have no effect"
    )

    reached = ca.dispose_package_versions(
        domain=domain, repository=repo, versions=["1.0.0"], **scope)
    assert reached["successfulVersions"]["1.0.0"]["status"] == "Disposed", (
        f"the positive control (DisposePackageVersions, the operation that owns this transition) "
        f"reported {reached['successfulVersions']!r} / {reached['failedVersions']!r}"
    )
    assert ca.describe_package_version(
        domain=domain, repository=repo, packageVersion="1.0.0", **scope
    )["packageVersion"]["status"] == "Disposed", (
        "the control's transition is not visible on a read-back"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
