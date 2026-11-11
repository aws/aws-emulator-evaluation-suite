"""rulegroup-concurrent-updates-single-winner."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rulegroup-concurrent-updates-single-winner"
GROUP = "concurrency"
SERVICES = ["wafv2"]

_LOCK_MESSAGE = (
    "AWS WAF couldn\u2019t save your changes because someone changed the resource after you "
    "started to edit it. Reapply your changes."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two UpdateRuleGroup calls racing on the same LockToken: exactly one
    wins and its rule persists, the other is rejected with
    WAFOptimisticLockException."""
    wafv2 = ctx.client("wafv2")
    scope = "REGIONAL"
    name = ctx.unique_name("sim2real-behav-rulegroup-")

    created = wafv2.create_rule_group(
        Name=name,
        Scope=scope,
        Capacity=100,
        VisibilityConfig={
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": name,
        },
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Summary"]
    rule_group_id = created["Id"]

    def _get():
        return wafv2.get_rule_group(Name=name, Scope=scope, Id=rule_group_id)

    def _delete():
        current = _get()
        wafv2.delete_rule_group(Name=name, Scope=scope, Id=rule_group_id, LockToken=current["LockToken"])

    ctx.on_cleanup(_delete)

    lock_token = created["LockToken"]
    base_visibility = {
        "SampledRequestsEnabled": True,
        "CloudWatchMetricsEnabled": True,
        "MetricName": name,
    }

    def _rule(country):
        return {
            "Name": f"racer-{country}",
            "Priority": 0,
            "Action": {"Count": {}},
            "Statement": {"GeoMatchStatement": {"CountryCodes": [country]}},
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": f"racer-{country}",
            },
        }

    def _racer(country):
        try:
            resp = wafv2.update_rule_group(
                Name=name,
                Scope=scope,
                Id=rule_group_id,
                VisibilityConfig=base_visibility,
                Rules=[_rule(country)],
                LockToken=lock_token,
            )
            return ("ok", country, resp["NextLockToken"])
        except ClientError as e:
            return ("error", country, e.response["Error"]["Code"], e.response["Error"].get("Message"))

    candidates = ["US", "CA"]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_racer, candidates))

    outcomes = [r[0] for r in results]
    assert outcomes.count("ok") == 1, f"expected exactly one winner, got {results}"
    assert outcomes.count("error") == 1, f"expected exactly one loser, got {results}"

    loser = next(r for r in results if r[0] == "error")
    assert loser[2] == "WAFOptimisticLockException", (
        f"expected the loser's rejection to be WAFOptimisticLockException, got {loser[2]!r}"
    )
    assert loser[3] == _LOCK_MESSAGE, f"unexpected WAFOptimisticLockException message {loser[3]!r}"

    winner_country, winner_next_token = next((r[1], r[2]) for r in results if r[0] == "ok")
    final = _get()
    rule_names = [r["Name"] for r in final["RuleGroup"]["Rules"]]
    assert rule_names == [f"racer-{winner_country}"], (
        f"expected persisted rules to be exactly the winner's [racer-{winner_country}], got {rule_names}"
    )
    assert final["LockToken"] == winner_next_token, (
        f"expected the persisted LockToken to be the winner's NextLockToken "
        f"({winner_next_token!r}), got {final['LockToken']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
