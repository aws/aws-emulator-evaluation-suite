"""associate-web-acl-nonexistent-distribution-fails."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "associate-web-acl-nonexistent-distribution-fails"
GROUP = "overly-permissive"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateDistributionWebACL on a well-formed but nonexistent distribution id fails with
    EntityNotFound "The specified distribution does not exist." and creates nothing, while the
    same call (same IfMatch and WebACLArn) on a real distribution persists the web ACL."""
    cf = ctx.client("cloudfront")
    web_acl_arn = _create_cloudfront_web_acl(ctx)
    dist_id, etag = _create_distribution(ctx)
    fake_dist_id = "EDFAKE0000000X"

    # Negative: the distribution id is syntactically well-formed but doesn't exist.
    code, msg = _error(
        lambda: cf.associate_distribution_web_acl(Id=fake_dist_id, WebACLArn=web_acl_arn, IfMatch=etag)
    )
    assert code == "EntityNotFound", f"expected EntityNotFound, got {code!r}"
    assoc_msg = "The specified distribution does not exist."
    assert msg == assoc_msg, f"expected message {assoc_msg!r}, got {msg!r}"

    # Effect absent: there is genuinely no such distribution to have been mutated.
    get_code, get_msg = _error(lambda: cf.get_distribution(Id=fake_dist_id))
    assert get_code == "NoSuchDistribution", f"expected NoSuchDistribution, got {get_code!r}"
    no_such_msg = "The specified distribution does not exist."
    assert get_msg == no_such_msg, f"expected message {no_such_msg!r}, got {get_msg!r}"

    # Positive control: the identical call against a real distribution succeeds.
    assoc = cf.associate_distribution_web_acl(Id=dist_id, WebACLArn=web_acl_arn, IfMatch=etag)
    assert assoc["WebACLArn"] == web_acl_arn, f"expected WebACLArn {web_acl_arn!r}, got {assoc['WebACLArn']!r}"
    persisted = cf.get_distribution_config(Id=dist_id)
    persisted_acl = persisted["DistributionConfig"]["WebACLId"]
    assert persisted_acl == web_acl_arn, f"expected persisted WebACLId {web_acl_arn!r}, got {persisted_acl!r}"

    # Wait for Deployed in the body: CloudFront propagation routinely outlasts the teardown's
    # time budget, and the distribution can only be disabled and deleted once it is Deployed.
    _wait_until_deployed(cf, dist_id)


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises, so a
    target that accepts what AWS refuses fails on that, not on a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_cloudfront_web_acl(ctx) -> str:
    waf = ctx.client("wafv2")
    name = ctx.unique_name("sim2real-acl-")
    resp = waf.create_web_acl(
        Name=name,
        Scope="CLOUDFRONT",
        DefaultAction={"Allow": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": name.replace("-", "")[:128],
        },
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    summary = resp["Summary"]
    acl_id = summary["Id"]
    arn = summary["ARN"]

    def _cleanup():
        got = waf.get_web_acl(Name=name, Scope="CLOUDFRONT", Id=acl_id)
        waf.delete_web_acl(Name=name, Scope="CLOUDFRONT", Id=acl_id, LockToken=got["LockToken"])

    ctx.on_cleanup(_cleanup)
    return arn


def _create_distribution(ctx) -> tuple[str, str]:
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-assocwebacl-")
    config = {
        "CallerReference": caller_ref,
        "Comment": "associate-web-acl nonexistent-distribution check",
        "Enabled": False,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": "origin.example.com",
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "https-only",
                    },
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
        },
    }
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": config,
            "Tags": {"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
        }
    )
    dist_id = resp["Distribution"]["Id"]
    etag = resp["ETag"]

    def _cleanup():
        # By the time cleanup runs, the body has already waited for Deployed (see
        # _wait_until_deployed), so this is a single fast call -- well inside the 60s
        # ctx.on_cleanup budget. Enabled is already False from creation.
        current = cf.get_distribution(Id=dist_id)["ETag"]
        cf.delete_distribution(Id=dist_id, IfMatch=current)

    ctx.on_cleanup(_cleanup)
    return dist_id, etag


def _wait_until_deployed(cf, dist_id: str, timeout_s: float = 840.0, interval_s: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = cf.get_distribution(Id=dist_id)["Distribution"]["Status"]
        if status == "Deployed":
            return
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} did not reach Deployed within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
