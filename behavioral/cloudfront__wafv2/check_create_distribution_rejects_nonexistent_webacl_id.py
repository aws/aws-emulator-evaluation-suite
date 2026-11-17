"""create-distribution-rejects-nonexistent-webacl-id."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-distribution-rejects-nonexistent-webacl-id"
GROUP = "overly-permissive"
SERVICES = ["cloudfront", "wafv2"]

_SCOPE = "CLOUDFRONT"
#: AWS managed cache policy "Managed-CachingDisabled" (public id; no account can create its own).
_CACHING_DISABLED_POLICY_ID = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
_INVALID_WEBACL = ("InvalidWebACLId", "Web ACL is not accessible by the requester.")


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
    """Delete the web ACL, retrying once on a stale LockToken; a nonexistent ACL is not an error."""
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
            if exc.response["Error"]["Code"] == "WAFNonexistentItemException":
                return
            if exc.response["Error"]["Code"] != "WAFOptimisticLockException":
                raise
    raise AssertionError(f"web ACL {acl_id} kept losing the lock race; not deleted")


def _distribution_config(caller_reference: str, comment: str, web_acl_arn: str | None) -> dict:
    config = {
        "CallerReference": caller_reference,
        "Comment": comment,
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
    }
    if web_acl_arn is not None:
        config["WebACLId"] = web_acl_arn
    return config


def _wait_deployed(cf, dist_id: str, timeout_s: float = 1500.0, interval_s: float = 15.0) -> str:
    """Poll GetDistribution until Status is Deployed; returns the current ETag."""
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = cf.get_distribution(Id=dist_id)
        last_status = resp["Distribution"]["Status"]
        if last_status == "Deployed":
            return resp["ETag"]
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} never reached Deployed, last status {last_status!r}")


def _delete_distribution(cf, dist_id: str) -> None:
    """Delete the distribution once it is Deployed; a distribution already gone is not an error."""
    try:
        etag = _wait_deployed(cf, dist_id)
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


def _comments_listed(cf) -> list[str]:
    comments: list[str] = []
    kwargs: dict = {}
    while True:
        resp = cf.list_distributions(**kwargs)
        items = resp.get("DistributionList", {}).get("Items") or []
        comments.extend(i["Comment"] for i in items)
        marker = resp.get("DistributionList", {}).get("NextMarker")
        if not marker:
            return comments
        kwargs["Marker"] = marker


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDistribution rejects a WebACLId that does not resolve to an existing web ACL with
    InvalidWebACLId and creates nothing, while the same call succeeds with a real one.

    Reference: https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_CreateDistribution.html
    """
    waf = ctx.client("wafv2", region="us-east-1")
    cf = ctx.client("cloudfront", region="us-east-1")

    bogus_name = ctx.unique_name("sim2real-behav-cfacl-missing-")
    bogus_acl_arn = (
        f"arn:aws:wafv2:us-east-1:{ctx.account}:global/webacl/{bogus_name}/"
        "00000000-0000-0000-0000-000000000000"
    )
    bogus_comment = ctx.unique_name("sim2real-behav-dist-bogus-")
    bogus_ref = ctx.unique_name("sim2real-behav-dist-bogus-")

    code, message = _error(
        lambda: cf.create_distribution(
            DistributionConfig=_distribution_config(bogus_ref, bogus_comment, bogus_acl_arn)
        )
    )
    assert (code, message) == _INVALID_WEBACL, (code, message)

    comments = _comments_listed(cf)
    assert bogus_comment not in comments, (
        f"a distribution commented {bogus_comment!r} exists after its CreateDistribution "
        "was rejected"
    )

    acl_name = ctx.unique_name("sim2real-behav-cfacl-real-")
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

    real_comment = ctx.unique_name("sim2real-behav-dist-real-")
    real_ref = ctx.unique_name("sim2real-behav-dist-real-")
    dist = cf.create_distribution(
        DistributionConfig=_distribution_config(real_ref, real_comment, acl_arn)
    )["Distribution"]
    dist_id = dist["Id"]
    ctx.on_cleanup(lambda: _delete_distribution(cf, dist_id))
    assert dist["DistributionConfig"]["WebACLId"] == acl_arn, (
        f"distribution {dist_id} WebACLId is {dist['DistributionConfig']['WebACLId']!r}, "
        f"expected {acl_arn!r}"
    )

    fetched = cf.get_distribution(Id=dist_id)["Distribution"]
    assert fetched["DistributionConfig"]["WebACLId"] == acl_arn, (
        f"GetDistribution for {dist_id} returned WebACLId "
        f"{fetched['DistributionConfig']['WebACLId']!r}, expected {acl_arn!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
