"""update-webacl-concurrent-lock-token-conflict-rejected."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-webacl-concurrent-lock-token-conflict-rejected"
GROUP = "error-semantics"
SERVICES = ["wafv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Of two concurrent UpdateWebACL calls with the same LockToken, exactly one succeeds and the other
    fails with WAFOptimisticLockException; GetWebACL returns the winner's Description and NextLockToken.
    """
    wafv2 = ctx.client("wafv2")

    webacl_name = ctx.unique_name("sim2real-behav-webacl-")
    created = wafv2.create_web_acl(
        Name=webacl_name,
        Scope="REGIONAL",
        DefaultAction={"Allow": {}},
        VisibilityConfig=_visibility_config(webacl_name),
    )["Summary"]
    webacl_id = created["Id"]
    lock_token = created["LockToken"]
    ctx.on_cleanup(lambda: _best_effort_delete_webacl(wafv2, webacl_name, webacl_id))

    def _update_with_description(description: str):
        return wafv2.update_web_acl(
            Name=webacl_name,
            Scope="REGIONAL",
            Id=webacl_id,
            DefaultAction={"Allow": {}},
            VisibilityConfig=_visibility_config(webacl_name),
            Description=description,
            LockToken=lock_token,
        )

    results: dict[str, Any] = {}

    def _race(label: str, description: str):
        try:
            resp = _update_with_description(description)
            results[label] = ("ok", resp["NextLockToken"])
        except ClientError as err:
            results[label] = ("error", err.response["Error"]["Code"])

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(_race, "a", "racer-a-description"),
            pool.submit(_race, "b", "racer-b-description"),
        ]
        for f in futures:
            f.result()

    outcomes = list(results.values())
    successes = [o for o in outcomes if o[0] == "ok"]
    failures = [o for o in outcomes if o[0] == "error"]

    assert len(successes) == 1, f"expected exactly one winner, got {outcomes}"
    assert len(failures) == 1, f"expected exactly one loser, got {outcomes}"
    assert failures[0][1] == "WAFOptimisticLockException", (
        f"expected the loser to fail with WAFOptimisticLockException, got {failures[0][1]!r}"
    )

    winner_label = "a" if results["a"][0] == "ok" else "b"
    winner_description = "racer-a-description" if winner_label == "a" else "racer-b-description"
    winner_next_token = results[winner_label][1]

    final = wafv2.get_web_acl(Name=webacl_name, Scope="REGIONAL", Id=webacl_id)
    assert final["WebACL"]["Description"] == winner_description, (
        f"expected persisted Description to be the winner's {winner_description!r}, "
        f"got {final['WebACL'].get('Description')!r}"
    )
    assert final["LockToken"] == winner_next_token, (
        f"expected persisted LockToken to be the winner's NextLockToken {winner_next_token!r}, "
        f"got {final['LockToken']!r}"
    )


def _visibility_config(metric_name: str) -> dict:
    return {
        "SampledRequestsEnabled": True,
        "CloudWatchMetricsEnabled": True,
        "MetricName": metric_name.replace(".", ""),
    }


def _best_effort_delete_webacl(wafv2, name: str, webacl_id: str) -> None:
    try:
        current = wafv2.get_web_acl(Name=name, Scope="REGIONAL", Id=webacl_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
            raise
        return
    try:
        wafv2.delete_web_acl(
            Name=name, Scope="REGIONAL", Id=webacl_id, LockToken=current["LockToken"]
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
