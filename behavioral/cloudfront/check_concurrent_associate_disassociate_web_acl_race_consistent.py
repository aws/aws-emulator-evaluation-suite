"""concurrent-associate-disassociate-web-acl-race-consistent."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-associate-disassociate-web-acl-race-consistent"
GROUP = "concurrency"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing AssociateDistributionWebACL and DisassociateDistributionWebACL on one ETag yields one
    winner and one PreconditionFailed loser, and the final WebACLId matches only the winner."""
    cf = ctx.client("cloudfront")
    # WAFv2 CLOUDFRONT-scope web ACLs are global but must be managed through the us-east-1
    # endpoint (any other region answers WAFInvalidParameterException "The scope is not
    # valid."), so the client is pinned through ctx.client(..., region=).
    waf = ctx.client("wafv2", region="us-east-1")
    origin_domain = f"{ctx.unique_name('sim2real-waf-')}.s3.amazonaws.com"

    distribution_config = {
        "CallerReference": ctx.unique_name("sim2real-wafd-"),
        "Comment": "sim2real waf race test",
        "Enabled": True,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": origin_domain,
                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",  # Managed-CachingOptimized
        },
    }
    # Tagged so a Resource Groups Tagging API search finds any remainder if cleanup is cut short.
    created = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": distribution_config,
            "Tags": {"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
        }
    )
    dist_id = created["Distribution"]["Id"]
    etag0 = created["ETag"]

    ctx.on_cleanup(lambda: _cleanup_distribution(cf, dist_id))

    acl_tags = [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]
    acl1 = waf.create_web_acl(
        Name=ctx.unique_name("sim2realWaf1"),
        Scope="CLOUDFRONT",
        DefaultAction={"Allow": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": False,
            "CloudWatchMetricsEnabled": False,
            "MetricName": ctx.unique_name("sim2realWaf1"),
        },
        Rules=[],
        Tags=acl_tags,
    )
    acl2 = waf.create_web_acl(
        Name=ctx.unique_name("sim2realWaf2"),
        Scope="CLOUDFRONT",
        DefaultAction={"Allow": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": False,
            "CloudWatchMetricsEnabled": False,
            "MetricName": ctx.unique_name("sim2realWaf2"),
        },
        Rules=[],
        Tags=acl_tags,
    )

    arn1 = acl1["Summary"]["ARN"]
    arn2 = acl2["Summary"]["ARN"]

    ctx.on_cleanup(
        lambda: _cleanup_all(cf, waf, dist_id, [acl1["Summary"], acl2["Summary"]])
    )

    # Establish a known baseline association (not raced).
    assoc1 = cf.associate_distribution_web_acl(Id=dist_id, IfMatch=etag0, WebACLArn=arn1)
    etag1 = assoc1["ETag"]

    def race_disassociate():
        try:
            resp = cf.disassociate_distribution_web_acl(Id=dist_id, IfMatch=etag1)
            return ("ok", "disassociate", resp["ETag"], None)
        except ClientError as exc:
            return ("error", "disassociate", exc.response["Error"]["Code"], exc.response["Error"].get("Message"))

    def race_associate2():
        try:
            resp = cf.associate_distribution_web_acl(Id=dist_id, IfMatch=etag1, WebACLArn=arn2)
            return ("ok", "associate2", resp["ETag"], None)
        except ClientError as exc:
            return ("error", "associate2", exc.response["Error"]["Code"], exc.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(race_disassociate), pool.submit(race_associate2)]
        results = [f.result() for f in futures]

    outcomes = {status for status, _, _, _ in results}
    assert outcomes == {"ok", "error"}, f"expected exactly one winner and one loser, got {results}"

    loser = next(r for r in results if r[0] == "error")
    # Both InvalidIfMatchVersion and PreconditionFailed are declared errors here, but AWS answers
    # a stale yet well-formed ETag with PreconditionFailed.
    assert loser[2] == "PreconditionFailed", f"expected PreconditionFailed, got {loser[2]}"
    if loser[1] == "associate2":
        assert loser[3] == "Your request is missing requirements for this operation. Update your request and try again.", (
            f"AssociateDistributionWebACL PreconditionFailed message: {loser[3]!r}"
        )

    winner_action = next(r for r in results if r[0] == "ok")[1]

    final_cfg = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
    final_web_acl_id = final_cfg["WebACLId"]

    if winner_action == "disassociate":
        assert final_web_acl_id == "", f"expected no WAF association, got {final_web_acl_id}"
    else:
        assert final_web_acl_id == arn2, f"expected {arn2}, got {final_web_acl_id}"
    # Never a torn state: the original association must not still be in place.
    assert final_web_acl_id != arn1, f"torn state: pre-race WebACLId {arn1} still in place"


# ===== helpers =====


def _poll_until(probe, predicate, timeout_s=1200, interval_s=20):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last}")


def _cleanup_distribution(cf, dist_id):
    try:
        cfg = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise
        return
    try:
        dconfig = cfg["DistributionConfig"]
        etag = cfg["ETag"]
        if dconfig.get("Enabled"):
            dconfig["Enabled"] = False
            upd = cf.update_distribution(DistributionConfig=dconfig, Id=dist_id, IfMatch=etag)
            etag = upd["ETag"]
        result = _poll_until(
            lambda: cf.get_distribution(Id=dist_id),
            lambda r: r["Distribution"]["Status"] == "Deployed",
            timeout_s=1200,
            interval_s=20,
        )
        cf.delete_distribution(Id=dist_id, IfMatch=result["ETag"])
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


def _cleanup_all(cf, waf, dist_id, webacl_summaries):
    _cleanup_distribution(cf, dist_id)
    for summary in webacl_summaries:
        # The web ACL stays associated (WAFAssociatedItemException) until the distribution
        # delete propagates; a concurrent edit answers WAFOptimisticLockException.
        deadline = time.monotonic() + 120
        while True:
            try:
                current = waf.get_web_acl(
                    Name=summary["Name"], Scope="CLOUDFRONT", Id=summary["Id"]
                )
                waf.delete_web_acl(
                    Name=summary["Name"],
                    Scope="CLOUDFRONT",
                    Id=summary["Id"],
                    LockToken=current["LockToken"],
                )
                break
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "WAFNonexistentItemException":
                    break
                if code not in ("WAFAssociatedItemException", "WAFOptimisticLockException"):
                    raise
                if time.monotonic() >= deadline:
                    raise
                time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
