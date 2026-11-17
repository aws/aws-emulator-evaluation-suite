"""delete-webacl-blocked-while-cloudfront-distribution-names-it."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-webacl-blocked-while-cloudfront-distribution-names-it"
GROUP = "overly-permissive"
SERVICES = ["cloudfront", "wafv2"]

_SCOPE = "CLOUDFRONT"
#: AWS managed cache policy "Managed-CachingDisabled" (public id; no account can create its own).
_CACHING_DISABLED_POLICY_ID = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
_ASSOCIATED = (
    "WAFAssociatedItemException",
    "AWS WAF couldn’t perform the operation because your resource is being used by "
    "another resource or it’s associated with another resource.",
)
_NONEXISTENT_MESSAGE = "AWS WAF couldn’t perform the operation because your resource doesn’t exist."


def _visibility(metric: str) -> dict:
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": metric}


def _error(fn) -> tuple[str, str]:
    """The (code, message) of the ClientError fn raises; a success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _delete_web_acl(waf, name: str, acl_id: str) -> None:
    """Delete the web ACL, retrying a lock race or a lingering association; raises if it survives."""
    for _ in range(3):
        try:
            current = waf.get_web_acl(Name=name, Scope=_SCOPE, Id=acl_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "WAFNonexistentItemException":
                return
            raise
        try:
            waf.delete_web_acl(
                Name=name, Scope=_SCOPE, Id=acl_id, LockToken=current["LockToken"]
            )
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "WAFNonexistentItemException":
                return
            if code not in ("WAFOptimisticLockException", "WAFAssociatedItemException"):
                raise
    raise AssertionError(f"web ACL {acl_id} still undeleted after retrying")


def _distribution_config(caller_reference: str, web_acl_arn: str) -> dict:
    return {
        "CallerReference": caller_reference,
        "Comment": "sim2real-behav-dist",
        "Enabled": False,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "sim2real-origin",
                    "DomainName": "origin.example.com",
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
            "TargetOriginId": "sim2real-origin",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": _CACHING_DISABLED_POLICY_ID,
        },
        "WebACLId": web_acl_arn,
    }


def _wait_deployed(cf, dist_id: str, timeout_s: float = 1500.0, interval_s: float = 15.0) -> dict:
    """Poll GetDistribution until Status is Deployed; returns the full response."""
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = cf.get_distribution(Id=dist_id)
        last_status = resp["Distribution"]["Status"]
        if last_status == "Deployed":
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} never reached Deployed, last status {last_status!r}")


def _delete_distribution(cf, dist_id: str) -> None:
    """Delete the distribution once it is Deployed; a distribution already gone is not an error."""
    try:
        etag = _wait_deployed(cf, dist_id)["ETag"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise
    try:
        cf.delete_distribution(Id=dist_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteWebACL on a CLOUDFRONT-scope WebACL is rejected with WAFAssociatedItemException
    while a fully deployed CloudFront distribution's WebACLId names it; clearing the
    distribution's WebACLId through UpdateDistribution lets the same delete succeed.

    Reference: https://docs.aws.amazon.com/waf/latest/APIReference/API_DeleteWebACL.html
    """
    waf = ctx.client("wafv2", region="us-east-1")
    cf = ctx.client("cloudfront", region="us-east-1")

    acl_name = ctx.unique_name("sim2real-behav-cfacl-")
    created = waf.create_web_acl(
        Name=acl_name,
        Scope=_SCOPE,
        DefaultAction={"Allow": {}},
        VisibilityConfig=_visibility(acl_name.replace("-", "")),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Summary"]
    acl_id = created["Id"]
    acl_arn = created["ARN"]
    ctx.on_cleanup(lambda: _delete_web_acl(waf, acl_name, acl_id))

    caller_reference = ctx.unique_name("sim2real-behav-dist-")
    dist = cf.create_distribution(
        DistributionConfig=_distribution_config(caller_reference, acl_arn)
    )["Distribution"]
    dist_id = dist["Id"]
    ctx.on_cleanup(lambda: _delete_distribution(cf, dist_id))

    deployed = _wait_deployed(cf, dist_id)
    assert deployed["Distribution"]["DistributionConfig"]["WebACLId"] == acl_arn, (
        f"deployed distribution {dist_id} WebACLId is "
        f"{deployed['Distribution']['DistributionConfig']['WebACLId']!r}, expected {acl_arn!r}"
    )

    lock_token = waf.get_web_acl(Name=acl_name, Scope=_SCOPE, Id=acl_id)["LockToken"]
    code, message = _error(
        lambda: waf.delete_web_acl(Name=acl_name, Scope=_SCOPE, Id=acl_id, LockToken=lock_token)
    )
    assert (code, message) == _ASSOCIATED, (code, message)

    still_there = waf.get_web_acl(Name=acl_name, Scope=_SCOPE, Id=acl_id)
    assert still_there["WebACL"]["Id"] == acl_id, (
        f"web ACL {acl_id} vanished after a rejected DeleteWebACL"
    )

    config = deployed["Distribution"]["DistributionConfig"]
    config["WebACLId"] = ""
    cf.update_distribution(Id=dist_id, IfMatch=deployed["ETag"], DistributionConfig=config)
    cleared = _wait_deployed(cf, dist_id)
    assert cleared["Distribution"]["DistributionConfig"]["WebACLId"] == "", (
        f"distribution {dist_id} WebACLId is "
        f"{cleared['Distribution']['DistributionConfig']['WebACLId']!r} after clearing it, "
        "expected an empty string"
    )

    final_lock_token = waf.get_web_acl(Name=acl_name, Scope=_SCOPE, Id=acl_id)["LockToken"]
    waf.delete_web_acl(Name=acl_name, Scope=_SCOPE, Id=acl_id, LockToken=final_lock_token)

    code_after, message_after = _error(
        lambda: waf.get_web_acl(Name=acl_name, Scope=_SCOPE, Id=acl_id)
    )
    assert code_after == "WAFNonexistentItemException", (
        f"expected WAFNonexistentItemException after delete, got {code_after!r}"
    )
    assert message_after == _NONEXISTENT_MESSAGE, message_after


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
