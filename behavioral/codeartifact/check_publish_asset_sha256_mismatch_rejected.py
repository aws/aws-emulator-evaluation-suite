"""publish-asset-sha256-mismatch-rejected."""
from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publish-asset-sha256-mismatch-rejected"
GROUP = 'package-assets-rejected'
SERVICES = ['codeartifact']


def _error(fn):
    """Call fn(); return (code, message). An unexpected SUCCESS is a hard failure."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"the call SUCCEEDED where real AWS rejects it and returned {result!r}"
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


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A publish whose assetSHA256 does not match the bytes is refused with a ValidationException naming
    the declared and the computed digest and stores no 2.0.0, while the correctly declared publish of
    the same bytes lands as Published and serves them back."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-ca-dom-")
    repo = ctx.unique_name("sim2real-behav-ca-repo-")
    package = "sim2real-integrity"
    payload = b"the-bytes-that-are-actually-sent\n"
    other = b"the-bytes-whose-digest-was-declared\n"
    scope = dict(format="generic", namespace="sim2real", package=package)

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))
    ca.create_repository(domain=domain, repository=repo, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))

    ca.publish_package_version(
        domain=domain, repository=repo, packageVersion="1.0.0", assetContent=payload,
        assetName="payload.bin", assetSHA256=hashlib.sha256(payload).hexdigest(), **scope)
    ctx.on_cleanup(lambda: ca.delete_package(domain=domain, repository=repo, **scope))

    declared = hashlib.sha256(other).hexdigest()
    computed = hashlib.sha256(payload).hexdigest()
    refusal = _error(lambda: ca.publish_package_version(
        domain=domain, repository=repo, packageVersion="2.0.0", assetContent=payload,
        assetName="payload.bin", assetSHA256=declared, **scope))
    expected = (
        "ValidationException",
        f"The provided content hashes do not match the calculated content hashes. Hash algorithm "
        f"'SHA-256', Expected hash '{declared}', Actual hash '{computed}'",
    )
    assert refusal == expected, (
        f"a publish with a mismatched assetSHA256 returned {refusal!r}, expected {expected!r}: the "
        f"refusal names the declared digest and the digest it COMPUTED from the bytes, which is "
        f"what proves the service hashed the payload rather than trusting the header"
    )

    versions = []
    for page in ca.get_paginator("list_package_versions").paginate(
            domain=domain, repository=repo, **scope):
        versions.extend(page["versions"])
    assert [v["version"] for v in versions] == ["1.0.0"], (
        f"after the refused publish the package holds {[v['version'] for v in versions]!r}, "
        f"expected only the pre-existing ['1.0.0'] — a rejected publish must store nothing"
    )

    landed = ca.publish_package_version(
        domain=domain, repository=repo, packageVersion="2.0.0", assetContent=payload,
        assetName="payload.bin", assetSHA256=hashlib.sha256(payload).hexdigest(), **scope)
    assert landed["status"] == "Published", (
        f"the positive control (same bytes, correct digest) reported {landed['status']!r}, "
        f"expected Published"
    )
    assert ca.get_package_version_asset(
        domain=domain, repository=repo, packageVersion="2.0.0", asset="payload.bin", **scope
    )["asset"].read() == payload, "the control publish did not store the bytes it was given"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
