"""op-contract-copy-distribution."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-copy-distribution"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CopyDistribution: creates a real staging distribution from a primary's config
    (Staging=True, distinct Id, same origin), and rejects a malformed If-Match with the
    specific InvalidIfMatchVersion code."""
    cf = ctx.client("cloudfront")
    primary_id, primary_etag = _create_minimal_distribution(ctx)

    resp = cf.copy_distribution(
        PrimaryDistributionId=primary_id,
        IfMatch=primary_etag,
        Staging=True,
        CallerReference=ctx.unique_name("sim2real-behav-copy-"),
        Enabled=False,
    )
    staging = resp["Distribution"]
    staging_id = staging["Id"]
    ctx.on_cleanup(lambda: _delete_distribution_best_effort(ctx, staging_id))

    assert staging_id != primary_id, f"copy must mint a distinct id, got {staging_id!r} == primary {primary_id!r}"
    assert staging["ARN"].endswith(staging_id), f"ARN {staging['ARN']!r} does not reference staging id {staging_id!r}"

    # Independent read at the destination: don't trust the mutating call's own echo for what
    # was actually persisted, and confirm the one property that makes this a staging copy at
    # all (Staging=True lives in DistributionConfig, not as a top-level Distribution field).
    persisted = cf.get_distribution(Id=staging_id)["Distribution"]["DistributionConfig"]
    assert persisted["Staging"] is True, (
        f"CopyDistribution(Staging=True) must persist a staging distribution; "
        f"GetDistribution reports Staging={persisted.get('Staging')!r}"
    )
    origins = persisted["Origins"]["Items"]
    assert origins[0]["DomainName"] == "example.com", "staging copy must inherit primary origin config"

    # Error boundary: malformed If-Match is rejected distinctly from a stale-but-valid one.
    code, message = _error(
        lambda: cf.copy_distribution(
            PrimaryDistributionId=primary_id,
            IfMatch="not-a-real-etag",
            Staging=True,
            CallerReference=ctx.unique_name("sim2real-behav-copy2-"),
        )
    )
    assert code == "InvalidIfMatchVersion", f"expected InvalidIfMatchVersion, got {code}"
    expected = "The If-Match version is missing or not valid for the resource."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises: an emulator accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_minimal_distribution(ctx):
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-behav-dist-")
    config = {
        "CallerReference": caller_ref,
        "Comment": caller_ref,
        "Enabled": False,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "primary-origin",
                    "DomainName": "example.com",
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "https-only",
                        "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                    },
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "primary-origin",
            "ViewerProtocolPolicy": "redirect-to-https",
            "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",  # CachingOptimized
        },
    }
    resp = cf.create_distribution(DistributionConfig=config)
    dist_id = resp["Distribution"]["Id"]
    etag = resp["ETag"]
    ctx.on_cleanup(lambda: _delete_distribution_best_effort(ctx, dist_id))
    return dist_id, etag


def _delete_distribution_best_effort(ctx, dist_id):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + 900.0
    try:
        while time.monotonic() < deadline:
            resp = cf.get_distribution(Id=dist_id)
            if resp["Distribution"]["Status"] == "Deployed":
                cf.delete_distribution(Id=dist_id, IfMatch=resp["ETag"])
                return
            time.sleep(15)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
