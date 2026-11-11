"""e2e-sampling-rule-affects-target-then-cleanup."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "e2e-sampling-rule-affects-target-then-cleanup"
GROUP = "e2e"
SERVICES = ["xray"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A created sampling rule's FixedRate/ReservoirSize are honored by GetSamplingTargets and
    exercised by GetSamplingStatisticSummaries; after DeleteSamplingRule it disappears from
    GetSamplingRules (the authoritative lifecycle boundary)."""
    xray = ctx.client("xray")
    rule_name = ctx.unique_name("sim2real-rule-")[:32]
    fixed_rate = 0.08
    reservoir_size = 4

    xray.create_sampling_rule(
        SamplingRule={
            "RuleName": rule_name,
            "ResourceARN": "*",
            "Priority": 9500,
            "FixedRate": fixed_rate,
            "ReservoirSize": reservoir_size,
            "ServiceName": "*",
            "ServiceType": "*",
            "Host": "*",
            "HTTPMethod": "*",
            "URLPath": "*",
            "Version": 1,
        },
        Tags=[{"Key": "simparity-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_rule_if_present(xray, rule_name))

    client_id = uuid.uuid4().hex[:24]

    def _get_target():
        stats_doc = {
            "RuleName": rule_name,
            "ClientID": client_id,
            "Timestamp": time.time(),
            "RequestCount": 10,
            "SampledCount": 2,
            "BorrowCount": 0,
        }
        resp = xray.get_sampling_targets(SamplingStatisticsDocuments=[stats_doc])
        assert resp["UnprocessedStatistics"] == [], (
            f"live rule's statistics were unexpectedly unprocessed: {resp['UnprocessedStatistics']!r}"
        )
        return next(t for t in resp["SamplingTargetDocuments"] if t["RuleName"] == rule_name)

    # X-Ray only starts handing out a ReservoirQuota once it has seen statistics from a
    # client for this rule, so poll (reporting fresh statistics each time) until it appears.
    target = _poll_until(_get_target, lambda t: "ReservoirQuota" in t, timeout_s=60, interval_s=5)
    assert target["FixedRate"] == fixed_rate, (
        f"expected FixedRate {fixed_rate}, target reported {target['FixedRate']!r}"
    )
    assert 0 <= target["ReservoirQuota"] <= reservoir_size, (
        f"expected ReservoirQuota in [0, {reservoir_size}], got {target['ReservoirQuota']!r}"
    )

    summaries_resp = xray.get_sampling_statistic_summaries()
    assert isinstance(summaries_resp.get("SamplingStatisticSummaries"), list), (
        f"expected a list of summaries, got {summaries_resp.get('SamplingStatisticSummaries')!r}"
    )

    xray.delete_sampling_rule(RuleName=rule_name)

    def _rule_gone() -> bool:
        names = {r["SamplingRule"]["RuleName"] for r in xray.get_sampling_rules()["SamplingRuleRecords"]}
        return rule_name not in names

    assert _poll_until(_rule_gone, lambda ok: ok, timeout_s=30, interval_s=2), (
        f"rule {rule_name} still listed by GetSamplingRules after delete"
    )

    def _post_delete_target():
        resp = xray.get_sampling_targets(
            SamplingStatisticsDocuments=[
                {
                    "RuleName": rule_name,
                    "ClientID": client_id,
                    "Timestamp": time.time(),
                    "RequestCount": 10,
                    "SampledCount": 2,
                    "BorrowCount": 0,
                }
            ]
        )
        unprocessed = {u["RuleName"] for u in resp["UnprocessedStatistics"]}
        processed = {t["RuleName"]: t for t in resp["SamplingTargetDocuments"]}
        return unprocessed, processed

    # Confirmed real AWS behavior: GetSamplingTargets computes a target purely from the reported
    # statistics document and does not re-validate that the named rule still exists. It keeps
    # returning the same allocation for a deleted rule's name rather than erroring or marking it
    # unprocessed. The real lifecycle boundary is GetSamplingRules, already confirmed above.
    unprocessed_names, processed_docs = _post_delete_target()
    assert rule_name not in unprocessed_names, (
        f"deleted rule's statistics were marked unprocessed, contradicting the "
        f"confirmed real-AWS behavior of continuing to serve a cached target: "
        f"{unprocessed_names!r}"
    )
    assert rule_name in processed_docs, (
        f"deleted rule stopped producing a cached sampling target: {processed_docs!r}"
    )
    assert processed_docs[rule_name]["FixedRate"] == fixed_rate, (
        f"cached target for the deleted rule drifted from its FixedRate: "
        f"{processed_docs[rule_name]!r}"
    )


# ===== helpers =====

def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _delete_rule_if_present(xray, rule_name: str) -> None:
    """Teardown: "Sampling rule does not exist" is clean; any other refusal is a failure."""
    from botocore.exceptions import ClientError

    try:
        xray.delete_sampling_rule(RuleName=rule_name)
    except ClientError as e:
        if e.response.get("Error", {}).get("Message") != "Sampling rule does not exist":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
