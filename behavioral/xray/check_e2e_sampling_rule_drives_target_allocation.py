"""e2e-sampling-rule-drives-target-allocation."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-sampling-rule-drives-target-allocation"
GROUP = "e2e"
SERVICES = ["xray"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Reported statistics for a new sampling rule yield a matching GetSamplingTargets allocation
    and statistic summary; a deleted rule leaves GetSamplingRules at once while GetSamplingTargets
    keeps a zero-sum reservoir for it (full quota to the known client, zero to a new one)."""
    xray = ctx.client("xray")

    rule_name = ctx.unique_name("sim2real-alloc-")[:32]
    priority = random.randint(100, 9000)
    fixed_rate = 0.42
    reservoir_size = 15
    client_id = _hex(24)

    xray.create_sampling_rule(
        SamplingRule={
            "RuleName": rule_name,
            "ResourceARN": "*",
            "Priority": priority,
            "FixedRate": fixed_rate,
            "ReservoirSize": reservoir_size,
            "ServiceName": "*",
            "ServiceType": "*",
            "Host": "*",
            "HTTPMethod": "*",
            "URLPath": "*",
            "Version": 1,
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    rule_created = True

    def _cleanup_rule():
        if rule_created:
            try:
                xray.delete_sampling_rule(RuleName=rule_name)
            except ClientError as e:
                if e.response.get("Error", {}).get("Message") != "Sampling rule does not exist":
                    raise

    ctx.on_cleanup(_cleanup_rule)

    stats_doc = {
        "RuleName": rule_name,
        "ClientID": client_id,
        "Timestamp": time.time(),
        "RequestCount": 500,
        "SampledCount": 50,
        "BorrowCount": 0,
    }
    targets = xray.get_sampling_targets(SamplingStatisticsDocuments=[stats_doc])
    assert targets.get("UnprocessedStatistics", []) == []
    target = next(
        (t for t in targets["SamplingTargetDocuments"] if t["RuleName"] == rule_name), None
    )
    assert target is not None, f"expected an allocation for {rule_name}: {targets}"
    assert target["FixedRate"] == fixed_rate
    # ReservoirQuota is only populated once X-Ray has computed a quota change
    # for this rule; it is not guaranteed to be present on the very first
    # statistics report, so poll a few more reporting rounds for it to
    # appear. As the sole reporting client, the rule's entire reservoir
    # should end up allocated to us.
    def _report_and_get_target():
        resp = xray.get_sampling_targets(
            SamplingStatisticsDocuments=[
                {
                    "RuleName": rule_name,
                    "ClientID": client_id,
                    "Timestamp": time.time(),
                    "RequestCount": 500,
                    "SampledCount": 50,
                    "BorrowCount": 0,
                }
            ]
        )
        return next(
            (t for t in resp["SamplingTargetDocuments"] if t["RuleName"] == rule_name), None
        )

    target_with_quota = _poll_until(
        _report_and_get_target,
        lambda t: t is not None and "ReservoirQuota" in t,
        timeout_s=60,
        interval_s=10,
    )
    assert target_with_quota["ReservoirQuota"] == reservoir_size


    summaries = _poll_until(
        lambda: xray.get_sampling_statistic_summaries()["SamplingStatisticSummaries"],
        lambda rows: any(r["RuleName"] == rule_name for r in rows),
        timeout_s=60,
        interval_s=5,
    )
    row = next(r for r in summaries if r["RuleName"] == rule_name)
    assert row["RequestCount"] == 500
    assert row["SampledCount"] == 50

    # Delete the rule -- GetSamplingRules (the control-plane read, independent
    # of the mutation) must never see it again. The data-plane target
    # computation is a *separate* code path that does not consult the rule
    # store per call: a client already known to the rule keeps being handed a
    # live target -- FixedRate, ReservoirQuota and a freshly-computed
    # ReservoirQuotaTTL -- with UnprocessedStatistics staying empty, exactly
    # as if the rule still existed. The fresh TTL is computed relative to the
    # *call* time, not the original allocation.
    xray.delete_sampling_rule(RuleName=rule_name)
    rule_created = False

    assert _find_rule(xray, rule_name) is None

    after_delete = xray.get_sampling_targets(
        SamplingStatisticsDocuments=[
            {
                "RuleName": rule_name,
                "ClientID": client_id,
                "Timestamp": time.time(),
                "RequestCount": 1,
                "SampledCount": 1,
                "BorrowCount": 0,
            }
        ]
    )
    unprocessed_after = [
        u for u in after_delete.get("UnprocessedStatistics", []) if u["RuleName"] == rule_name
    ]
    assert unprocessed_after == [], (
        f"expected the deleted rule to keep serving its already-known client "
        f"rather than surface it as unprocessed: {after_delete}"
    )
    stale_target = next(
        (t for t in after_delete["SamplingTargetDocuments"] if t["RuleName"] == rule_name), None
    )
    assert stale_target is not None, (
        f"expected the deleted rule to keep handing its known client a target: {after_delete}"
    )
    assert stale_target["ReservoirQuota"] == reservoir_size, (
        f"expected the stale target to keep the rule's full reservoir: {stale_target}"
    )

    # A brand new client that never reported to this (now-deleted) rule
    # before is still served by the same rule-name-keyed target computation
    # (it is not turned away, and its
    # UnprocessedStatistics stays empty too) -- but the reservoir is
    # zero-sum per rule, and the whole reservoir was already claimed by
    # `client_id` above, so the newcomer's share of it must be exactly zero.
    # This is the allocation invariant the CHECK is named for, observed to
    # keep holding even once the rule that created it is gone.
    fresh_client_id = _hex(24)
    fresh_report = xray.get_sampling_targets(
        SamplingStatisticsDocuments=[
            {
                "RuleName": rule_name,
                "ClientID": fresh_client_id,
                "Timestamp": time.time(),
                "RequestCount": 1,
                "SampledCount": 1,
                "BorrowCount": 0,
            }
        ]
    )
    fresh_target = next(
        (t for t in fresh_report["SamplingTargetDocuments"] if t["RuleName"] == rule_name), None
    )
    fresh_unprocessed = [
        u for u in fresh_report.get("UnprocessedStatistics", []) if u["RuleName"] == rule_name
    ]
    assert fresh_unprocessed == [], (
        f"expected the deleted rule's target computation to still answer a "
        f"brand-new client rather than mark it unprocessed: {fresh_report}"
    )
    assert fresh_target is not None, (
        f"expected the deleted rule to still hand a target to a brand-new client: {fresh_report}"
    )
    assert fresh_target["ReservoirQuota"] == 0, (
        f"expected a client with no claim on an already-fully-allocated "
        f"reservoir to get none of it: {fresh_target}"
    )



# ===== helpers =====
def _hex(n: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value: {last}")
        time.sleep(interval_s)


def _find_rule(xray, rule_name: str):
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = xray.get_sampling_rules(**kwargs)
        for record in resp.get("SamplingRuleRecords", []):
            if record["SamplingRule"]["RuleName"] == rule_name:
                return record
        next_token = resp.get("NextToken")
        if not next_token:
            return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
