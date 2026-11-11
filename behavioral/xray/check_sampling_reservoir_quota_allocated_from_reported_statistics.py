"""sampling-reservoir-quota-allocated-from-reported-statistics."""
from __future__ import annotations

import datetime
import random
import time

from behavioral_harness import tags

CHECK = "sampling-reservoir-quota-allocated-from-reported-statistics"
GROUP = 'sampling-rules'
SERVICES = ['xray']

#: The service's allocation cycle takes ~12-20 s; the bound is generous but finite.
_TARGET_TIMEOUT_S = 300
_SUMMARY_TIMEOUT_S = 300


def _hex(n: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def _default_sampling_rule(name, **overrides):
    rule = {
        "RuleName": name,
        "ResourceARN": "*",
        # A low-precedence priority band so this rule never shadows a real client's rule.
        "Priority": random.randint(9000, 9899),
        "FixedRate": 0.1,
        "ReservoirSize": 1,
        "ServiceName": "*",
        "ServiceType": "*",
        "Host": "*",
        "HTTPMethod": "*",
        "URLPath": "*",
        "Version": 1,
    }
    rule.update(overrides)
    return rule


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, timeout_s=60, interval_s=5, description="condition", ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _sampling_rule_records(xr, max_pages=25):
    out = {}
    token = None
    for _ in range(max_pages):
        page = xr.get_sampling_rules(**({"NextToken": token} if token else {}))
        for record in page.get("SamplingRuleRecords", []):
            name = (record.get("SamplingRule") or {}).get("RuleName")
            if name:
                out[name] = record
        token = page.get("NextToken")
        if not token:
            break
    return out


def _delete_rule_and_confirm(xr, rule_name, timeout_s=60):
    xr.delete_sampling_rule(RuleName=rule_name)
    _poll_until(
        lambda: _sampling_rule_records(xr),
        lambda records: rule_name not in records,
        timeout_s=timeout_s,
        interval_s=2,
        description=f"sampling rule {rule_name} absent from GetSamplingRules after delete",
    )


def _report(xr, rule_name, client_id, requests_seen, sampled):
    """One SamplingStatisticsDocument report, the call an instrumented process makes on a timer."""
    return xr.get_sampling_targets(SamplingStatisticsDocuments=[{
        "RuleName": rule_name,
        "ClientID": client_id,
        "Timestamp": datetime.datetime.now(datetime.timezone.utc),
        "RequestCount": requests_seen,
        "SampledCount": sampled,
        "BorrowCount": 0,
    }])


def _statistic_summaries(xr, max_pages=25):
    out = {}
    token = None
    for _ in range(max_pages):
        page = xr.get_sampling_statistic_summaries(**({"NextToken": token} if token else {}))
        for summary in page.get("SamplingStatisticSummaries", []):
            if summary.get("RuleName"):
                out.setdefault(summary["RuleName"], []).append(summary)
        token = page.get("NextToken")
        if not token:
            break
    return out


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """GetSamplingTargets allocates a reservoir: the first report gets no ReservoirQuota, later ones
    get the rule's ReservoirSize (5 and 1) with a future TTL, and a second client gets 0.

    Reference: https://docs.aws.amazon.com/xray/latest/api/API_GetSamplingTargets.html
    """
    xr = ctx.client("xray")
    big_name = ctx.unique_name("sim2real-bh-xr5-")
    small_name = ctx.unique_name("sim2real-bh-xr1-")

    created_big = xr.create_sampling_rule(
        SamplingRule=_default_sampling_rule(big_name, ReservoirSize=5, FixedRate=0.1),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_rule_and_confirm(xr, big_name))
    created_small = xr.create_sampling_rule(
        SamplingRule=_default_sampling_rule(small_name, ReservoirSize=1, FixedRate=0.1),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_rule_and_confirm(xr, small_name))
    assert created_big["SamplingRuleRecord"]["SamplingRule"]["ReservoirSize"] == 5, created_big
    assert created_small["SamplingRuleRecord"]["SamplingRule"]["ReservoirSize"] == 1, created_small

    client_big = _hex(24)
    client_small = _hex(24)

    # The first report on a fresh rule precedes the first allocation cycle: no reservoir.
    first = _report(xr, big_name, client_big, 100, 10)
    assert first.get("UnprocessedStatistics", []) == [], (
        f"a well-formed statistics document for an existing rule must be processed: {first!r}"
    )
    first_targets = first["SamplingTargetDocuments"]
    assert [t["RuleName"] for t in first_targets] == [big_name], (
        f"exactly one target document for the one reported rule: {first_targets!r}"
    )
    assert first_targets[0]["FixedRate"] == 0.1, (
        f"the target must serve the rule's FixedRate, not a default: {first_targets[0]!r}"
    )
    assert "ReservoirQuota" not in first_targets[0], (
        f"the very first report against a rule precedes the service's first allocation cycle for "
        f"it, so no reservoir can have been granted yet -- an implementation that answers with a "
        f"quota immediately is inventing state it does not have: {first_targets[0]!r}"
    )
    _report(xr, small_name, client_small, 100, 10)

    before_call = time.time()
    clients = {big_name: client_big, small_name: client_small}
    granted: dict = {}

    def _report_ungranted():
        for name, client in clients.items():
            if name not in granted:
                target = _report(xr, name, client, 100, 10)["SamplingTargetDocuments"][0]
                if "ReservoirQuota" in target:
                    granted[name] = target
        return dict(granted)

    _poll_until(
        _report_ungranted,
        lambda got: big_name in got and small_name in got,
        timeout_s=_budget_s(ctx, _TARGET_TIMEOUT_S),
        interval_s=2,
        description=f"a ReservoirQuota granted to the reporting clients for {big_name} and {small_name}",
        ctx=ctx,
    )
    big_target = granted[big_name]
    small_target = granted[small_name]

    assert big_target["ReservoirQuota"] == 5, (
        f"the sole client reporting against a ReservoirSize=5 rule must be granted the whole "
        f"reservoir; an implementation handing out an unbounded reservoir lets a client sample "
        f"everything, and a constant fails against the size-1 rule below: {big_target!r}"
    )
    assert small_target["ReservoirQuota"] == 1, (
        f"the same reporting pattern against a ReservoirSize=1 rule must be granted 1, which is "
        f"what proves the quota tracks the RULE rather than being a constant: {small_target!r}"
    )
    assert big_target["ReservoirQuotaTTL"].timestamp() > before_call, (
        f"ReservoirQuotaTTL must lie in the future or the quota is unusable the moment it is "
        f"issued: {big_target['ReservoirQuotaTTL']!r} against {before_call!r}"
    )
    assert big_target["Interval"] > 0, (
        f"Interval tells the client when to report again and must be positive: {big_target!r}"
    )
    assert big_target["FixedRate"] == 0.1, big_target

    second_client = _report(xr, big_name, _hex(24), 0, 0)["SamplingTargetDocuments"][0]
    assert "ReservoirQuota" in second_client, (
        f"once a rule has an active allocation cycle every reporting client must be told its "
        f"share, even when that share is zero: {second_client!r}"
    )
    assert second_client["ReservoirQuota"] == 0, (
        f"the first client already holds the whole ReservoirSize=5 reservoir under an unexpired "
        f"TTL, so a second client reporting zero requests must be granted nothing: "
        f"{second_client!r}"
    )
    assert big_target["ReservoirQuota"] + second_client["ReservoirQuota"] <= 5, (
        f"the reservoir handed out across clients must never exceed the rule's ReservoirSize of 5: "
        f"{big_target['ReservoirQuota']!r} + {second_client['ReservoirQuota']!r}"
    )

    # Summary RequestCount is not an echo of the reported counts, so only presence and shape
    # are asserted.
    summaries = _poll_until(
        lambda: _statistic_summaries(xr),
        lambda by_rule: big_name in by_rule and small_name in by_rule,
        timeout_s=_budget_s(ctx, _SUMMARY_TIMEOUT_S),
        interval_s=1,
        description="both reported rules present in GetSamplingStatisticSummaries",
        ctx=ctx,
    )
    for rule_name in (big_name, small_name):
        rows = summaries[rule_name]
        assert rows, (
            f"GetSamplingStatisticSummaries never reported {rule_name!r} after statistics were "
            f"reported against it; the one shipped check of this operation asserts only "
            f"isinstance(..., list), which a constant [] satisfies"
        )
        for row in rows:
            assert row["RequestCount"] >= 0 and row["SampledCount"] >= 0, row
            assert row["Timestamp"] is not None, (
                f"a statistics summary row must be stamped with the period it covers: {row!r}"
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
