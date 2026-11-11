"""e2e-webacl-regional-scope-association-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-webacl-regional-scope-association-rejected"
GROUP = "e2e"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateDistributionWebACL rejects a REGIONAL-scope web ACL and leaves WebACLId empty, while
    associating a CLOUDFRONT-scope web ACL succeeds (only that scope is valid for a distribution).
    """
    cf = ctx.client("cloudfront")
    waf = _waf(ctx, "REGIONAL")

    dist_id = _create_minimal_distribution(ctx)
    ctx.on_cleanup(lambda: _delete_distribution(ctx, dist_id))
    _wait_distribution_deployed(cf, dist_id)

    regional_acl = waf.create_web_acl(
        Name=ctx.unique_name("sim2real-cf-regacl-"),
        Scope="REGIONAL",
        DefaultAction={"Allow": {}},
        VisibilityConfig={"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": "default"},
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_web_acl(ctx, regional_acl["Name"], regional_acl["Id"], "REGIONAL"))

    etag = cf.get_distribution(Id=dist_id)["ETag"]
    code, message = _error(
        lambda: cf.associate_distribution_web_acl(Id=dist_id, WebACLArn=regional_acl["ARN"], IfMatch=etag)
    )
    assert code == "InvalidArgument", f"expected InvalidArgument for a REGIONAL-scope web ACL, got {code}"
    expected_message = (
        "The specified web ACL isn't valid. Specify a web ACL that was previously validated and try again."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect must be absent: the distribution has no web ACL associated.
    unchanged_config = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
    assert unchanged_config.get("WebACLId", "") == "", (
        f"expected no WebACLId after the rejected associate, got {unchanged_config.get('WebACLId', '')!r}"
    )

    # Positive control: a genuine CLOUDFRONT-scope web ACL associates successfully.
    cloudfront_acl = _waf(ctx, "CLOUDFRONT").create_web_acl(
        Name=ctx.unique_name("sim2real-cf-cfacl-"),
        Scope="CLOUDFRONT",
        DefaultAction={"Allow": {}},
        VisibilityConfig={"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": "default"},
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_web_acl(ctx, cloudfront_acl["Name"], cloudfront_acl["Id"], "CLOUDFRONT"))

    etag = cf.get_distribution(Id=dist_id)["ETag"]
    result = cf.associate_distribution_web_acl(Id=dist_id, WebACLArn=cloudfront_acl["ARN"], IfMatch=etag)
    assert result["WebACLArn"] == cloudfront_acl["ARN"], (
        f"expected associate to echo {cloudfront_acl['ARN']!r}, got {result['WebACLArn']!r}"
    )
    # Registered after the web ACL cleanups so LIFO disassociates first:
    # WAFv2 refuses to delete an associated ACL.
    ctx.on_cleanup(lambda: _disassociate_web_acl(ctx, dist_id))
    _wait_distribution_deployed(cf, dist_id)
    associated_config = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
    assert associated_config["WebACLId"] == cloudfront_acl["ARN"], (
        f"expected the independent read to show WebACLId {cloudfront_acl['ARN']!r}, "
        f"got {associated_config.get('WebACLId', '')!r}"
    )



def _error(fn) -> tuple[str, str]:
    """Run a call AWS refuses; return its (code, message). Raise if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


def _create_minimal_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    resp = cf.create_distribution(
        DistributionConfig={
            "CallerReference": ctx.unique_name("sim2real-cf-regacl-cr-"),
            "Comment": "sim2real behavioral: webacl scope mismatch rejection",
            "Enabled": True,
            "Origins": {
                "Quantity": 1,
                "Items": [
                    {
                        "Id": "custom-origin",
                        "DomainName": "example.com",
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
                "TargetOriginId": "custom-origin",
                "ViewerProtocolPolicy": "redirect-to-https",
                "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",  # AWS managed CachingOptimized
            },
        }
    )
    return resp["Distribution"]["Id"]


def _wait_distribution_deployed(cf, dist_id: str, timeout_s: float = 1500.0, interval_s: float = 20.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if cf.get_distribution(Id=dist_id)["Distribution"]["Status"] == "Deployed":
            return
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} never reached Deployed within {timeout_s}s")


def _waf(ctx, scope: str):
    """A WAFv2 client for ``scope``: CLOUDFRONT-scope web ACLs are managed only in us-east-1."""
    return ctx.client("wafv2", region="us-east-1") if scope == "CLOUDFRONT" else ctx.client("wafv2")


def _delete_web_acl(ctx, name: str, web_acl_id: str, scope: str) -> None:
    waf = _waf(ctx, scope)
    # Retry while a disassociation propagates (WAFAssociatedItemException) or a concurrent edit
    # moved the lock token (WAFOptimisticLockException); raise anything else.
    deadline = time.monotonic() + 120
    while True:
        try:
            lock_token = waf.get_web_acl(Name=name, Scope=scope, Id=web_acl_id)["LockToken"]
            waf.delete_web_acl(Name=name, Scope=scope, Id=web_acl_id, LockToken=lock_token)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "WAFNonexistentItemException":
                return
            if code not in ("WAFAssociatedItemException", "WAFOptimisticLockException"):
                raise
            if time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _disassociate_web_acl(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        config = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
        if not config.get("WebACLId"):
            return
        etag = cf.get_distribution(Id=dist_id)["ETag"]
        cf.disassociate_distribution_web_acl(Id=dist_id, IfMatch=etag)
        _wait_distribution_deployed(cf, dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("EntityNotFound", "NoSuchDistribution"):
            raise


def _delete_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        config_resp = cf.get_distribution_config(Id=dist_id)
        config = config_resp["DistributionConfig"]
        etag = config_resp["ETag"]
        if config.get("WebACLId"):
            etag = cf.get_distribution(Id=dist_id)["ETag"]
            cf.disassociate_distribution_web_acl(Id=dist_id, IfMatch=etag)
            _wait_distribution_deployed(cf, dist_id)
            config_resp = cf.get_distribution_config(Id=dist_id)
            config = config_resp["DistributionConfig"]
            etag = config_resp["ETag"]
        if config.get("Enabled"):
            config["Enabled"] = False
            cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=etag)
            _wait_distribution_deployed(cf, dist_id)
            etag = cf.get_distribution(Id=dist_id)["ETag"]
        cf.delete_distribution(Id=dist_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "EntityNotFound",
            "NoSuchCachePolicy",
            "NoSuchContinuousDeploymentPolicy",
            "NoSuchDistribution",
            "NoSuchFieldLevelEncryptionConfig",
            "NoSuchOrigin",
            "NoSuchOriginRequestPolicy",
            "NoSuchRealtimeLogConfig",
            "NoSuchResponseHeadersPolicy",
            "TrustedKeyGroupDoesNotExist",
            "TrustedSignerDoesNotExist",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
