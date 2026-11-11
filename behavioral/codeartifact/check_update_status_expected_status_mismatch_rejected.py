"""update-status-expected-status-mismatch-rejected."""
from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-status-expected-status-mismatch-rejected"
GROUP = 'package-version-status-rejected'
SERVICES = ['codeartifact']


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
    """A wrong expectedStatus is refused inside a 200: failedVersions reports MISMATCHED_STATUS, nothing
    succeeds and the version stays Unlisted; the call with the true status archives it."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-ca-dom-")
    repo = ctx.unique_name("sim2real-behav-ca-repo-")
    package = "sim2real-guarded-status"
    content = b"guarded-status-payload\n"
    scope = dict(format="generic", namespace="sim2real", package=package)

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))
    ca.create_repository(domain=domain, repository=repo,
                          tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))

    ca.publish_package_version(
        domain=domain, repository=repo, packageVersion="1.0.0", assetContent=content,
        assetName="payload.bin", assetSHA256=hashlib.sha256(content).hexdigest(), **scope)
    ctx.on_cleanup(lambda: ca.delete_package(domain=domain, repository=repo, **scope))

    ca.update_package_versions_status(domain=domain, repository=repo, versions=["1.0.0"],
                                     targetStatus="Unlisted", **scope)

    refused = ca.update_package_versions_status(
        domain=domain, repository=repo, versions=["1.0.0"], expectedStatus="Published",
        targetStatus="Archived", **scope)
    assert refused["successfulVersions"] == {}, (
        f"the guarded call reported successes {refused['successfulVersions']!r}; a mismatched "
        f"expectedStatus must apply nothing"
    )
    failure = refused["failedVersions"].get("1.0.0")
    assert failure is not None, (
        f"the guarded call reported failedVersions {refused['failedVersions']!r}, expected an "
        f"entry for 1.0.0"
    )
    assert failure["errorCode"] == "MISMATCHED_STATUS", (
        f"the per-version errorCode was {failure['errorCode']!r}, expected MISMATCHED_STATUS"
    )

    unchanged = ca.describe_package_version(
        domain=domain, repository=repo, packageVersion="1.0.0", **scope)["packageVersion"]
    assert unchanged["status"] == "Unlisted", (
        f"the refused call still moved the version to {unchanged['status']!r}; a rejection must "
        f"leave the status at Unlisted"
    )

    applied = ca.update_package_versions_status(
        domain=domain, repository=repo, versions=["1.0.0"], expectedStatus="Unlisted",
        targetStatus="Archived", **scope)
    assert applied["failedVersions"] == {}, (
        f"the positive control (expectedStatus=Unlisted, the true status) reported failures "
        f"{applied['failedVersions']!r}"
    )
    assert applied["successfulVersions"]["1.0.0"]["status"] == "Archived", (
        f"the control reported {applied['successfulVersions']!r}, expected 1.0.0 Archived"
    )
    assert ca.describe_package_version(
        domain=domain, repository=repo, packageVersion="1.0.0", **scope
    )["packageVersion"]["status"] == "Archived", (
        "the control's transition is not visible on a read-back"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
