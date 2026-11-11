"""op-contract-associate-distribution-web-acl."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-associate-distribution-web-acl"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateDistributionWebACL with a CLOUDFRONT-scope WAFv2 web ACL sets the distribution's WebACLId;
    repeating it with the superseded ETag is refused with PreconditionFailed and the exact message and
    leaves WebACLId unchanged, and the same call with the current ETag succeeds."""

    cf = ctx.client("cloudfront")
    # WAFv2 CLOUDFRONT-scope web ACLs are global but must be managed through the us-east-1
    # endpoint (any other region answers WAFInvalidParameterException "The scope is not
    # valid."). Pinned through ctx.client(..., region=) rather than aborting on ctx.region, so
    # the same code path runs against every target -- an emulator keeps its shared endpoint.
    wafv2 = ctx.client("wafv2", region="us-east-1")

    acl_name = ctx.unique_name("sim2real-behav-acl-")
    acl = wafv2.create_web_acl(
        Name=acl_name,
        Scope="CLOUDFRONT",
        DefaultAction={"Allow": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": acl_name.replace("-", ""),
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Summary"]
    acl_arn = acl["ARN"]
    ctx.on_cleanup(lambda: wafv2.delete_web_acl(Name=acl_name, Scope="CLOUDFRONT", Id=acl["Id"], LockToken=_current_lock_token(wafv2, acl_name, acl["Id"])))

    dist_id, etag = _create_minimal_distribution(ctx)

    # Success path: association actually rewires the distribution config.
    resp = cf.associate_distribution_web_acl(Id=dist_id, IfMatch=etag, WebACLArn=acl_arn)
    assert resp["Id"] == dist_id, f"expected response Id {dist_id!r}, got {resp['Id']!r}"
    assert resp["WebACLArn"] == acl_arn, f"expected response WebACLArn {acl_arn!r}, got {resp['WebACLArn']!r}"
    cfg = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
    assert cfg["WebACLId"] == acl_arn, f"WebACLId not propagated: {cfg.get('WebACLId')!r}"

    # Error boundary: reusing the superseded (but well-formed) ETag must fail with
    # PreconditionFailed; a malformed ETag string gets InvalidIfMatchVersion instead.
    code, message = _error(lambda: cf.associate_distribution_web_acl(Id=dist_id, IfMatch=etag, WebACLArn=acl_arn))
    assert code == "PreconditionFailed", f"expected PreconditionFailed, got {code}"
    expected = (
        "Your request is missing requirements for this operation. Update your request and try again."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The rejected call must not have perturbed state: an independent read still shows the
    # association from the earlier successful call, unchanged.
    after_reject = cf.get_distribution_config(Id=dist_id)
    assert after_reject["DistributionConfig"]["WebACLId"] == acl_arn, (
        f"WebACLId changed after a rejected associate call: {after_reject['DistributionConfig'].get('WebACLId')!r}"
    )

    # Restore leg: a fresh ETag lets the identical association go through, proving the
    # rejection above was about the stale precondition and not the association itself.
    restored = cf.associate_distribution_web_acl(Id=dist_id, IfMatch=after_reject["ETag"], WebACLArn=acl_arn)
    assert restored["WebACLArn"] == acl_arn, (
        f"expected restore call to succeed with WebACLArn {acl_arn!r}, got {restored.get('WebACLArn')!r}"
    )


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


def _current_lock_token(wafv2, name, acl_id):
    return wafv2.get_web_acl(Name=name, Scope="CLOUDFRONT", Id=acl_id)["LockToken"]


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
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": config,
            "Tags": {"Items": [{"Key": "sim2real", "Value": CHECK}]},
        }
    )
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
