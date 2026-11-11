"""e2e-sampling-rule-lifecycle-affects-sampling-targets."""
from __future__ import annotations

import json
import random
import time
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "e2e-sampling-rule-lifecycle-affects-sampling-targets"
GROUP = "e2e"
SERVICES = ["xray"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetSamplingTargets reports a new rule's FixedRate and picks up an UpdateSamplingRule change;
    after DeleteSamplingRule the rule leaves GetSamplingRules while GetSamplingTargets keeps serving
    its last FixedRate to a client still reporting usage under that name."""
    xray = ctx.client("xray")
    # XRay SamplingRule RuleName is capped at 32 chars; ctx.unique_name appends a
    # 12-hex-char suffix, so the prefix itself must stay <= 20 chars.
    rule_name = ctx.unique_name("sim2real-lc-rule-")
    priority = 5000 + (abs(hash(rule_name)) % 4000)

    xray.create_sampling_rule(
        SamplingRule={
            "RuleName": rule_name,
            "ResourceARN": "*",
            "Priority": priority,
            "FixedRate": 0.05,
            "ReservoirSize": 1,
            "ServiceName": "*",
            "ServiceType": "*",
            "Host": "*",
            "HTTPMethod": "*",
            "URLPath": "*",
            "Version": 1,
        },
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    state = {"deleted": False}
    # Held steady across calls: the sampling-target cache is keyed by (RuleName, ClientID)
    # history, and an unknown client gets no target at all.
    client_id = _make_client_id()

    def _cleanup():
        if not state["deleted"]:
            xray.delete_sampling_rule(RuleName=rule_name)

    ctx.on_cleanup(_cleanup)

    # A trace segment the rule (ServiceName="*") would match.
    now = time.time()
    segment = {
        "trace_id": _make_trace_id(),
        "id": _make_segment_id(),
        "name": ctx.unique_name("sim2real-lcsvc-"),
        "start_time": now - 2,
        "end_time": now - 1,
    }
    put_resp = xray.put_trace_segments(TraceSegmentDocuments=[json.dumps(segment)])
    assert put_resp.get("UnprocessedTraceSegments", []) == [], (
        f"segment rejected: {put_resp.get('UnprocessedTraceSegments')}"
    )

    resp1 = _get_targets(xray, rule_name, client_id)
    docs1 = {d["RuleName"]: d for d in resp1.get("SamplingTargetDocuments", [])}
    unproc1 = {d["RuleName"] for d in resp1.get("UnprocessedStatistics", [])}
    assert rule_name not in unproc1, f"newly created rule was unprocessed: {resp1}"
    assert rule_name in docs1, "newly created rule produced no sampling target"
    assert abs(docs1[rule_name]["FixedRate"] - 0.05) < 1e-9, (
        f"expected FixedRate 0.05 for a freshly created rule, got {docs1[rule_name]}"
    )

    # The service-side sampling target cache refreshes on a short interval (~10 s), so poll.
    xray.update_sampling_rule(SamplingRuleUpdate={"RuleName": rule_name, "FixedRate": 0.5})
    docs2 = _poll_until(
        lambda: {
            d["RuleName"]: d
            for d in _get_targets(xray, rule_name, client_id).get("SamplingTargetDocuments", [])
        },
        lambda docs: rule_name in docs and abs(docs[rule_name]["FixedRate"] - 0.5) < 1e-9,
        timeout_s=90.0,
        interval_s=5.0,
    )
    assert rule_name in docs2, "updated rule produced no sampling target"
    assert abs(docs2[rule_name]["FixedRate"] - 0.5) < 1e-9, (
        f"target FixedRate did not reflect the update: {docs2[rule_name]}"
    )

    xray.delete_sampling_rule(RuleName=rule_name)
    state["deleted"] = True
    rec = _find_sampling_rule(ctx, rule_name)
    assert rec is None, "deleted rule is still listed by GetSamplingRules"

    # The target cache is driven by client-submitted statistics, not rule existence, so it keeps
    # serving the last FixedRate after deletion; this is not lag to poll past.
    final_resp = _get_targets(xray, rule_name, client_id)
    docs3 = {d["RuleName"]: d for d in final_resp.get("SamplingTargetDocuments", [])}
    assert rule_name in docs3, (
        f"deleted rule unexpectedly stopped producing a cached sampling target: {final_resp}"
    )
    assert abs(docs3[rule_name]["FixedRate"] - 0.5) < 1e-9, (
        f"cached target for the deleted rule drifted from its last known FixedRate: {docs3[rule_name]}"
    )


def _get_targets(xray, rule_name: str, client_id: str):
    stats_doc = {
        "RuleName": rule_name,
        "ClientID": client_id,
        "Timestamp": datetime.now(timezone.utc),
        "RequestCount": 10,
        "SampledCount": 1,
        "BorrowCount": 0,
    }
    return xray.get_sampling_targets(SamplingStatisticsDocuments=[stats_doc])


def _find_sampling_rule(ctx, rule_name: str):
    xray = ctx.client("xray")
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = xray.get_sampling_rules(**kwargs)
        for rec in resp.get("SamplingRuleRecords", []):
            if rec.get("SamplingRule", {}).get("RuleName") == rule_name:
                return rec
        token = resp.get("NextToken")
        if not token:
            return None


def _make_client_id() -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(24))


def _make_trace_id() -> str:
    epoch = format(int(time.time()), "x")[-8:].rjust(8, "0")
    rand = "".join(random.choice("0123456789abcdef") for _ in range(24))
    return f"1-{epoch}-{rand}"


def _make_segment_id() -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(16))


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
