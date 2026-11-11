"""op-contract-create-distribution."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-create-distribution"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDistribution returns an Id, a matching ARN and Location, a hostname DomainName and Status
    InProgress, which GetDistribution agrees with until it settles on Deployed, while a TargetOriginId
    naming no origin is refused with NoSuchOrigin and the exact message and creates no distribution."""
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-behav-dist-")
    config = _minimal_distribution_config(caller_ref, target_origin_id="primary-origin")

    resp = cf.create_distribution(DistributionConfig=config)
    dist = resp["Distribution"]
    dist_id = dist["Id"]
    ctx.on_cleanup(lambda: _delete_distribution_best_effort(ctx, dist_id))
    cf.tag_resource(Resource=dist["ARN"], Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]})

    assert dist["Id"], f"expected a non-empty Id, got {dist['Id']!r}"
    assert dist["ARN"].endswith(dist_id), f"expected ARN to end with {dist_id!r}, got {dist['ARN']!r}"
    assert re.fullmatch(r"[A-Za-z0-9.-]+(:\d+)?", dist["DomainName"]), (
        f"expected a hostname DomainName, got {dist['DomainName']!r}"
    )
    assert dist["Status"] == "InProgress", f"expected Status InProgress, got {dist['Status']!r}"
    assert resp["Location"].endswith(dist_id), (
        f"expected Location to end with {dist_id!r}, got {resp['Location']!r}"
    )

    # Independent read: the create response alone is not trusted. GetDistribution is a
    # different operation, at the same destination, and must agree with what create returned.
    described = cf.get_distribution(Id=dist_id)["Distribution"]
    assert described["Id"] == dist_id, f"expected GetDistribution Id {dist_id!r}, got {described['Id']!r}"
    assert described["ARN"] == dist["ARN"], (
        f"expected GetDistribution ARN {dist['ARN']!r}, got {described['ARN']!r}"
    )
    assert described["DomainName"] == dist["DomainName"], (
        f"expected GetDistribution DomainName {dist['DomainName']!r}, got {described['DomainName']!r}"
    )
    # The create answer is InProgress; by the time a separate read lands the distribution may
    # already have deployed, so that read accepts either documented status.
    assert described["Status"] in ("InProgress", "Deployed"), (
        f"expected GetDistribution Status InProgress or Deployed after create, got {described['Status']!r}"
    )
    deployed = _wait_deployed(cf, dist_id)
    assert deployed["Id"] == dist_id and deployed["Status"] == "Deployed", (
        f"expected distribution {dist_id!r} to settle on Deployed, got {deployed['Status']!r}"
    )

    # Error boundary: DefaultCacheBehavior.TargetOriginId referencing an origin that
    # doesn't exist in Origins.Items must fail with NoSuchOrigin specifically. This input
    # can never become valid for this request, so there is no restore leg.
    bad_caller_ref = ctx.unique_name("sim2real-behav-dist-bad-")
    bad_config = _minimal_distribution_config(bad_caller_ref, target_origin_id="does-not-exist")
    try:
        bad_resp = cf.create_distribution(DistributionConfig=bad_config)
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == "NoSuchOrigin", f"expected NoSuchOrigin, got {err['Code']}"
        expected = "One or more of your cache behavior target origins or origin groups do not exist."
        assert err.get("Message") == expected, (
            f"NoSuchOrigin message {err.get('Message')!r}, expected {expected!r}"
        )
    else:
        # AWS rejects this, so an accepted call fails as such, not as a code mismatch; the
        # created distribution's cleanup is registered before failing.
        bad_dist_id = bad_resp["Distribution"]["Id"]
        ctx.on_cleanup(lambda: _delete_distribution_best_effort(ctx, bad_dist_id))
        cf.tag_resource(
            Resource=bad_resp["Distribution"]["ARN"],
            Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
        )
        raise AssertionError(
            f"expected create_distribution to reject a TargetOriginId with no matching "
            f"Origin with NoSuchOrigin, but it SUCCEEDED and created {bad_dist_id!r}"
        )

    # Effect-absent, independent read: the rejected config must never have produced a
    # distribution — checked via ListDistributions, a different operation than the one
    # that was rejected.
    listed = cf.list_distributions().get("DistributionList", {}).get("Items", [])
    assert all(d.get("Comment") != bad_caller_ref for d in listed), (
        f"expected no distribution with Comment {bad_caller_ref!r} after NoSuchOrigin rejection"
    )


def _minimal_distribution_config(caller_ref, target_origin_id):
    return {
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
            "TargetOriginId": target_origin_id,
            "ViewerProtocolPolicy": "redirect-to-https",
            "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",  # CachingOptimized
        },
    }


def _wait_deployed(cf, dist_id, timeout_s=850.0, interval_s=15.0):
    """Poll GetDistribution until Status is Deployed; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        dist = cf.get_distribution(Id=dist_id)["Distribution"]
        status = dist["Status"]
        if status == "Deployed":
            return dist
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} never reached Deployed within {timeout_s}s, last={status!r}")


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
