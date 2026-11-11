"""webacl-concurrent-updates-single-winner."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "webacl-concurrent-updates-single-winner"
GROUP = "concurrency"
SERVICES = ["wafv2"]

_LOCK_MESSAGE = (
    "AWS WAF couldn\u2019t save your changes because someone changed the resource after you "
    "started to edit it. Reapply your changes."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateWebACL calls sharing a stale LockToken race to exactly
    one winner; the loser is rejected with WAFOptimisticLockException and the
    persisted state reflects only the winner's change, never a merge of both."""
    from botocore.exceptions import ClientError

    wafv2 = ctx.client("wafv2")
    name = ctx.unique_name("sim2real-webacl-")
    scope = "REGIONAL"
    vis = {"SampledRequestsEnabled": False, "CloudWatchMetricsEnabled": False, "MetricName": name}

    created = wafv2.create_web_acl(
        Name=name, Scope=scope, DefaultAction={"Allow": {}}, VisibilityConfig=vis,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    summary = created["Summary"]
    acl_id = summary["Id"]
    initial_lock_token = summary["LockToken"]

    def _cleanup():
        try:
            cur = wafv2.get_web_acl(Name=name, Scope=scope, Id=acl_id)
            wafv2.delete_web_acl(Name=name, Scope=scope, Id=acl_id, LockToken=cur["LockToken"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
                raise

    ctx.on_cleanup(_cleanup)

    def _update(desc: str):
        try:
            resp = wafv2.update_web_acl(
                Name=name,
                Scope=scope,
                Id=acl_id,
                DefaultAction={"Allow": {}},
                Description=desc,
                VisibilityConfig=vis,
                LockToken=initial_lock_token,
            )
            return ("ok", desc, resp["NextLockToken"])
        except ClientError as e:
            return ("err", desc, e.response["Error"]["Code"], e.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=2) as ex:
        futures = [ex.submit(_update, "update-A"), ex.submit(_update, "update-B")]
        results = [f.result() for f in futures]

    oks = [r for r in results if r[0] == "ok"]
    errs = [r for r in results if r[0] == "err"]

    assert len(oks) == 1, f"expected exactly one winner, got {results}"
    assert len(errs) == 1, f"expected exactly one loser, got {results}"
    assert errs[0][2] == "WAFOptimisticLockException", (
        f"expected the loser's rejection to be WAFOptimisticLockException, got {errs[0][2]!r}"
    )
    assert errs[0][3] == _LOCK_MESSAGE, f"unexpected WAFOptimisticLockException message {errs[0][3]!r}"

    winner_desc = oks[0][1]
    winner_next_token = oks[0][2]
    final = wafv2.get_web_acl(Name=name, Scope=scope, Id=acl_id)
    assert final["WebACL"]["Description"] == winner_desc, (
        "persisted Description does not match the sole winning update "
        f"(got {final['WebACL'].get('Description')!r}, winner submitted {winner_desc!r})"
    )
    assert final["LockToken"] == winner_next_token, (
        "persisted LockToken does not match the winner's own NextLockToken "
        f"(got {final['LockToken']!r}, winner's update returned {winner_next_token!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
