"""distribution-web-acl-disassociate-no-association-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "distribution-web-acl-disassociate-no-association-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"
_PRECONDITION_FAILED = (
    "Your request is missing requirements for this operation. Update your request and try again."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisassociateDistributionWebACL with an ETag from before the web ACL was associated is refused with
    PreconditionFailed and the exact message and leaves the association in place; with the current
    ETag it succeeds and clears WebACLId."""
    cf = ctx.client("cloudfront")

    dist_config = _minimal_distribution_config(
        caller_reference=ctx.unique_name("sim2real-webacl-dist-"),
        comment="sim2real web-acl disassociate-guard check",
    )
    created = cf.create_distribution(DistributionConfig=dist_config)
    dist_id = created["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, dist_id))

    stale_etag = created["ETag"]

    web_acl = _create_web_acl(ctx)
    current_etag = cf.get_distribution_config(Id=dist_id)["ETag"]
    assoc = cf.associate_distribution_web_acl(
        Id=dist_id, WebACLArn=web_acl["arn"], IfMatch=current_etag
    )
    assert assoc["WebACLArn"] == web_acl["arn"], (
        f"expected AssociateDistributionWebAcl to echo {web_acl['arn']!r}, got {assoc['WebACLArn']!r}"
    )

    after_assoc = cf.get_distribution_config(Id=dist_id)
    assert after_assoc["DistributionConfig"]["WebACLId"] == web_acl["arn"], (
        "expected the association to be visible via an independent GetDistributionConfig read, "
        f"got WebACLId={after_assoc['DistributionConfig'].get('WebACLId')!r}"
    )

    # The ETag captured before the association is out of date, so CloudFront must reject the
    # call on precondition grounds, not apply it against state that has changed.
    code, message = _error(
        lambda: cf.disassociate_distribution_web_acl(Id=dist_id, IfMatch=stale_etag)
    )
    assert code == "PreconditionFailed", (
        f"expected the stale-ETag disassociate to be rejected with PreconditionFailed, got {code!r}"
    )
    assert message == _PRECONDITION_FAILED, (
        f"expected message {_PRECONDITION_FAILED!r}, got {message!r}"
    )

    # Effect absent: the Web ACL is still associated, unaffected by the
    # rejected call.
    still_assoc = cf.get_distribution_config(Id=dist_id)
    assert still_assoc["DistributionConfig"]["WebACLId"] == web_acl["arn"], (
        "expected the rejected stale-ETag disassociate to leave the association untouched, got "
        f"WebACLId={still_assoc['DistributionConfig'].get('WebACLId')!r}"
    )

    # Positive control: the identical operation, same file, with the CURRENT
    # ETag succeeds and clears the association.
    disassoc = cf.disassociate_distribution_web_acl(
        Id=dist_id, IfMatch=still_assoc["ETag"]
    )
    assert disassoc["Id"] == dist_id, (
        f"expected DisassociateDistributionWebAcl to return Id={dist_id!r}, got {disassoc['Id']!r}"
    )

    after_disassoc = cf.get_distribution_config(Id=dist_id)
    assert not after_disassoc["DistributionConfig"].get("WebACLId"), (
        "expected the current-ETag disassociate to clear WebACLId via an independent read, still "
        f"got WebACLId={after_disassoc['DistributionConfig'].get('WebACLId')!r}"
    )


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, so a target
    that accepts a call AWS refuses fails as an accepted call, not as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError rejection but the call succeeded with {result!r}")


def _minimal_distribution_config(caller_reference: str, comment: str) -> dict[str, Any]:
    return {
        "CallerReference": caller_reference,
        "Comment": comment[:128],
        "Enabled": True,
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
                        "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                        "OriginReadTimeout": 30,
                        "OriginKeepaliveTimeout": 5,
                    },
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "primary-origin",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": _MANAGED_CACHING_OPTIMIZED,
        },
        "ViewerCertificate": {"CloudFrontDefaultCertificate": True},
    }


def _wafv2_cloudfront_client(ctx):
    """WAFv2 web ACLs with Scope="CLOUDFRONT" are global but must be managed via the us-east-1
    endpoint; any other region rejects with WAFInvalidParameterException ("The scope is not
    valid."). ctx.client pins that region on whichever target the run uses."""
    return ctx.client("wafv2", region="us-east-1")


def _create_web_acl(ctx) -> dict[str, str]:
    waf = _wafv2_cloudfront_client(ctx)
    name = ctx.unique_name("sim2real-cf-acl-")
    metric_name = "".join(ch for ch in name if ch.isalnum())[:128] or "sim2realcfacl"
    resp = waf.create_web_acl(
        Name=name,
        Scope="CLOUDFRONT",
        DefaultAction={"Allow": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": False,
            "CloudWatchMetricsEnabled": False,
            "MetricName": metric_name,
        },
        Rules=[],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    summary = resp["Summary"]
    web_acl_id = summary["Id"]

    def _cleanup() -> None:
        cur = waf.get_web_acl(Name=name, Scope="CLOUDFRONT", Id=web_acl_id)
        waf.delete_web_acl(
            Name=name, Scope="CLOUDFRONT", Id=web_acl_id, LockToken=cur["LockToken"]
        )

    ctx.on_cleanup(_cleanup)
    return {"arn": summary["ARN"], "id": web_acl_id, "name": name}


def _wait_distribution_status(
    ctx, dist_id: str, target_status: str, timeout_s: float = 1800.0, interval_s: float = 20.0
) -> dict[str, Any]:
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    last = None
    resp: dict[str, Any] = {}
    while time.monotonic() < deadline:
        resp = cf.get_distribution(Id=dist_id)
        last = resp["Distribution"]["Status"]
        if last == target_status:
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} never reached {target_status!r} (last={last!r})")


def _disable_and_delete_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        cf.update_distribution(Id=dist_id, DistributionConfig=cfg, IfMatch=cfg_resp["ETag"])
    resp = _wait_distribution_status(ctx, dist_id, "Deployed")
    cf.delete_distribution(Id=dist_id, IfMatch=resp["ETag"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
