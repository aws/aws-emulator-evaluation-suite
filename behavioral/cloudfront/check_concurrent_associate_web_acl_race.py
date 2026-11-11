"""concurrent-associate-web-acl-race."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-associate-web-acl-race"
GROUP = "concurrency"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent AssociateDistributionWebACL calls with the same ETag and different web ACLs:
    exactly one wins, the loser is rejected, and GetDistribution shows the winner's ACL cleanly.
    """
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    from botocore.exceptions import ClientError

    cf = ctx.client("cloudfront")
    waf = ctx.client("wafv2")

    # Distribution created (and its cleanup registered) first: LIFO teardown then runs the two
    # cheap web-ACL deletes before the slow disable/wait/delete distribution cleanup, so a
    # distribution teardown that overruns ctx.on_cleanup's 60s budget (a real risk -- deployment
    # can take far longer) never starves the fast cleanups behind it.
    dist_id, etag = _create_minimal_distribution(ctx, cf)

    web_acl_a = _create_cloudfront_web_acl(ctx, waf, "a", teardown_deadline)
    web_acl_b = _create_cloudfront_web_acl(ctx, waf, "b", teardown_deadline)
    # Runs before the web-ACL deletes: an ACL still associated with the distribution refuses deletion.
    ctx.on_cleanup(lambda: _disassociate_web_acl(cf, dist_id))

    def associate_with(arn: str):
        return cf.associate_distribution_web_acl(Id=dist_id, IfMatch=etag, WebACLArn=arn)

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(associate_with, web_acl_a["arn"])
        fut_b = pool.submit(associate_with, web_acl_b["arn"])
        results = []
        for fut, tag, arn in ((fut_a, "a", web_acl_a["arn"]), (fut_b, "b", web_acl_b["arn"])):
            try:
                resp = fut.result()
                results.append((tag, "ok", resp, arn, None))
            except ClientError as exc:
                results.append((tag, exc.response["Error"]["Code"], None, arn, exc.response["Error"].get("Message")))

    oks = [r for r in results if r[1] == "ok"]
    fails = [r for r in results if r[1] != "ok"]
    assert len(oks) == 1, f"expected exactly one winner, got {[(r[0], r[1]) for r in results]}"
    assert len(fails) == 1, f"expected exactly one loser, got {[(r[0], r[1]) for r in results]}"
    assert fails[0][1] in ("InvalidIfMatchVersion", "PreconditionFailed"), (
        f"loser should be rejected on the stale precondition, got {fails[0][1]}"
    )
    if fails[0][1] == "PreconditionFailed":
        assert fails[0][4] == "Your request is missing requirements for this operation. Update your request and try again.", (
            f"AssociateDistributionWebACL PreconditionFailed message: {fails[0][4]!r}"
        )

    winner_arn = oks[0][3]
    dist_cfg = cf.get_distribution(Id=dist_id)["Distribution"]["DistributionConfig"]
    assert dist_cfg["WebACLId"] == winner_arn, (
        f"final WebACLId {dist_cfg['WebACLId']!r} does not match the actual "
        f"winner {winner_arn!r} -- association was not atomic"
    )


# ===== helpers =====
def _create_cloudfront_web_acl(ctx, waf, suffix: str, teardown_deadline) -> dict:
    name = ctx.unique_name(f"sim2real-webacl-{suffix}-")
    resp = waf.create_web_acl(
        Name=name,
        Scope="CLOUDFRONT",
        DefaultAction={"Allow": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": False,
            "CloudWatchMetricsEnabled": False,
            "MetricName": name.replace("-", ""),
        },
        Rules=[],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    summary = resp["Summary"]
    ctx.on_cleanup(lambda: _delete_web_acl(waf, summary, teardown_deadline))
    return {"arn": summary["ARN"], "id": summary["Id"], "name": summary["Name"]}


# budget.cleanup_timeout for behavioral/cloudfront, one deadline shared by the web-ACL teardowns.
_TEARDOWN_RETRY_S = 1800.0


def _disassociate_web_acl(cf, dist_id: str) -> None:
    """Teardown: detach whichever web ACL won the race from the distribution."""
    cur = cf.get_distribution_config(Id=dist_id)
    if cur["DistributionConfig"].get("WebACLId"):
        cf.disassociate_distribution_web_acl(Id=dist_id, IfMatch=cur["ETag"])


def _delete_web_acl(waf, summary: dict, teardown_deadline) -> None:
    """Teardown DeleteWebACL: the detach reaches WAF asynchronously, so WAFAssociatedItemException
    is retried every 2 s to the cleanup deadline; WAFNonexistentItemException is gone."""
    from botocore.exceptions import ClientError

    deadline = teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S - 120.0)
    while True:
        try:
            lock = waf.get_web_acl(Name=summary["Name"], Scope="CLOUDFRONT", Id=summary["Id"])["LockToken"]
            waf.delete_web_acl(Name=summary["Name"], Scope="CLOUDFRONT", Id=summary["Id"], LockToken=lock)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "WAFNonexistentItemException":
                return
            if code != "WAFAssociatedItemException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _create_minimal_distribution(ctx, cf):
    origin_id = ctx.unique_name("sim2real-origin-")
    resp = cf.create_distribution(
        DistributionConfig={
            "CallerReference": ctx.unique_name("sim2real-dist-"),
            "Comment": "sim2real behavioral check",
            "Enabled": False,
            "Origins": {
                "Quantity": 1,
                "Items": [
                    {
                        "Id": origin_id,
                        "DomainName": "example.com",
                        "CustomOriginConfig": {
                            "HTTPPort": 80,
                            "HTTPSPort": 443,
                            "OriginProtocolPolicy": "https-only",
                        },
                    }
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": origin_id,
                "ViewerProtocolPolicy": "allow-all",
                "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
            },
        }
    )
    dist_id = resp["Distribution"]["Id"]
    etag = resp["ETag"]
    # create_distribution has no inline Tags param (unlike create_distribution_with_tags), and a
    # Resource Groups Tagging API scan never sees an untagged distribution, so tag explicitly to keep
    # a leaked distribution findable by tag.
    cf.tag_resource(
        Resource=resp["Distribution"]["ARN"],
        Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
    )
    ctx.on_cleanup(lambda: _delete_distribution(ctx, cf, dist_id))
    return dist_id, etag


def _delete_distribution(ctx, cf, dist_id: str) -> None:
    cur = cf.get_distribution_config(Id=dist_id)
    cfg, etag = cur["DistributionConfig"], cur["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    deadline = time.monotonic() + 1800
    while time.monotonic() < deadline:
        dist = cf.get_distribution(Id=dist_id)
        if dist["Distribution"]["Status"] == "Deployed":
            etag = dist["ETag"]
            break
        time.sleep(15)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
