"""disassociate-web-acl-invalid-argument-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "disassociate-web-acl-invalid-argument-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisassociateDistributionWebACL on a distribution with no web ACL succeeds as a no-op (WebACLId
    stays empty), while AssociateDistributionWebACL with a malformed WebACLArn is refused with
    InvalidArgument and the exact message and leaves WebACLId and the ETag unchanged."""
    cf = ctx.client("cloudfront")
    dist_id, etag = _create_minimal_distribution(ctx)

    # Baseline: a freshly created distribution has no WebACL association.
    baseline = cf.get_distribution(Id=dist_id)
    baseline_web_acl_id = baseline["Distribution"]["DistributionConfig"]["WebACLId"]
    assert baseline_web_acl_id == "", f"expected no WebACL on a fresh distribution, got {baseline_web_acl_id!r}"

    # Disassociating an unassociated distribution succeeds as a no-op, not InvalidArgument: the
    # response carries the distribution Id and WebACLId stays "".
    disassoc = cf.disassociate_distribution_web_acl(Id=dist_id, IfMatch=etag)
    assert disassoc["Id"] == dist_id, f"expected DisassociateDistributionWebACL to echo {dist_id!r}, got {disassoc['Id']!r}"

    after_noop = cf.get_distribution(Id=dist_id)
    after_noop_web_acl_id = after_noop["Distribution"]["DistributionConfig"]["WebACLId"]
    assert after_noop_web_acl_id == "", f"expected the idempotent no-op to leave WebACLId empty, got {after_noop_web_acl_id!r}"

    # AssociateDistributionWebACL rejects a malformed WebACLArn with InvalidArgument; CloudFront
    # validates the ARN's shape itself, without calling WAF.
    code, message = _error(
        lambda: cf.associate_distribution_web_acl(
            Id=dist_id, IfMatch=after_noop["ETag"], WebACLArn="not-a-valid-web-acl-arn"
        )
    )
    assert code == "InvalidArgument", f"expected InvalidArgument, got {code!r}"
    assert message == (
        "The specified web ACL isn't valid. Specify a web ACL that was previously validated and try again."
    ), f"unexpected InvalidArgument message: {message!r}"

    # Effect absent: the rejected association never touched the distribution.
    after_reject = cf.get_distribution(Id=dist_id)
    after_reject_web_acl_id = after_reject["Distribution"]["DistributionConfig"]["WebACLId"]
    assert after_reject_web_acl_id == "", f"expected the rejected AssociateDistributionWebACL to leave WebACLId empty, got {after_reject_web_acl_id!r}"
    assert after_reject["ETag"] == after_noop["ETag"], (
        f"expected the rejected call to leave the ETag at {after_noop['ETag']!r}, got {after_reject['ETag']!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _create_minimal_distribution(ctx) -> tuple[str, str]:
    """Create a minimal disabled CloudFront distribution; register its cleanup."""
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-behav-dist-")
    config = {
        "CallerReference": caller_ref,
        "Comment": "sim2real behavioral check",
        "Enabled": False,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "primary-origin",
                    "DomainName": "www.example.com",
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "https-only",
                    },
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "primary-origin",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",  # managed CachingOptimized
        },
    }
    resp = cf.create_distribution(DistributionConfig=config)
    dist_id = resp["Distribution"]["Id"]
    dist_arn = resp["Distribution"]["ARN"]
    etag = resp["ETag"]

    cf.tag_resource(
        Resource=dist_arn,
        Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
    )

    def _cleanup():
        final_etag = _wait_for_distribution_deployed(ctx, dist_id)
        cf.delete_distribution(Id=dist_id, IfMatch=final_etag)

    ctx.on_cleanup(_cleanup)
    return dist_id, etag


def _wait_for_distribution_deployed(ctx, dist_id: str, timeout_s: float = 1800.0, interval_s: float = 15.0) -> str:
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    last_etag = None
    while time.monotonic() < deadline:
        resp = cf.get_distribution(Id=dist_id)
        last_etag = resp["ETag"]
        if resp["Distribution"]["Status"] == "Deployed":
            return last_etag
        time.sleep(interval_s)
    # Best effort: return the last-seen ETag so delete_distribution can still be
    # attempted/surfaced clearly rather than silently swallowing the timeout.
    return last_etag


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
