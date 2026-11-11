"""describe-absent-package-version-reports-the-package."""
from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-absent-package-version-reports-the-package"
GROUP = 'package-read-not-authorized-or-absent'
SERVICES = ['codeartifact']


def _error(fn):
    """Call fn(); return the whole botocore Error dict. An unexpected SUCCESS is a hard failure."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"], exc.response
    raise AssertionError(
        "the read SUCCEEDED where real AWS rejects it — there is no error to compare"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An absent version 9.9.9 of a describable package is a 404 ResourceNotFoundException with
    resourceType "package", resourceId the package name and the exact package-not-found message,
    while the package and its version 1.0.0 both describe."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-ca-dom-")
    repo = ctx.unique_name("sim2real-behav-ca-repo-")
    package = "sim2real-present-package"
    content = b"present-package-payload\n"
    scope = dict(format="generic", namespace="sim2real", package=package)

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))
    ca.create_repository(domain=domain, repository=repo, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))
    ca.publish_package_version(
        domain=domain, repository=repo, packageVersion="1.0.0", assetContent=content,
        assetName="payload.bin", assetSHA256=hashlib.sha256(content).hexdigest(), **scope)
    ctx.on_cleanup(lambda: ca.delete_package(domain=domain, repository=repo, **scope))

    assert ca.describe_package(
        domain=domain, repository=repo, **scope)["package"]["name"] == package, (
        "the package must be describable, or the 404 below is about the package after all"
    )
    assert ca.describe_package_version(
        domain=domain, repository=repo, packageVersion="1.0.0", **scope
    )["packageVersion"]["version"] == "1.0.0", (
        "the existing version must be readable, or the 404 below proves nothing about versions"
    )

    error, response = _error(lambda: ca.describe_package_version(
        domain=domain, repository=repo, packageVersion="9.9.9", **scope))
    assert error["Code"] == "ResourceNotFoundException", (
        f"reading an absent version returned {error['Code']!r}, expected ResourceNotFoundException"
    )
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 404, (
        f"the refusal carried HTTP {response['ResponseMetadata']['HTTPStatusCode']!r}, expected 404"
    )
    assert response["resourceType"] == "package", (
        f"the refusal reports resourceType {response['resourceType']!r}; real AWS blames the "
        f"PACKAGE here even though the package exists and only the version is missing"
    )
    assert response["resourceId"] == package, (
        f"the refusal reports resourceId {response['resourceId']!r}, expected the package name "
        f"{package!r} rather than the version that was asked for"
    )
    assert error["Message"] == (
        "The generic package '%s' with namespace 'sim2real' does not exist in repository '%s'."
        % (package, repo)
    ), (
        f"the refusal said {error['Message']!r}; expected the package-level wording naming the "
        f"format, namespace and repository"
    )

    assert ca.describe_package(
        domain=domain, repository=repo, **scope)["package"]["name"] == package, (
        "the failed read disturbed the package"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
