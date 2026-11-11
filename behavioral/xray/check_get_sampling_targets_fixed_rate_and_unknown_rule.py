"""get-sampling-targets-fixed-rate-and-unknown-rule."""
from __future__ import annotations

import datetime
import random
import time

from behavioral_harness import tags

CHECK = "get-sampling-targets-fixed-rate-and-unknown-rule"
GROUP = 'sampling-rules'
SERVICES = ['xray']


def _hex(n: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def _default_sampling_rule(name, **overrides):
    rule = {
        "RuleName": name,
        "ResourceARN": "*",
        "Priority": random.randint(1, 9999),
        "FixedRate": 0.05,
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


def _poll_until(probe, predicate, timeout_s=60, interval_s=2, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _sampling_rule_names(xr, max_pages=25):
    names = set()
    token = None
    for _ in range(max_pages):
        page = xr.get_sampling_rules(**({"NextToken": token} if token else {}))
        for record in page.get("SamplingRuleRecords", []):
            name = (record.get("SamplingRule") or {}).get("RuleName")
            if name:
                names.add(name)
        token = page.get("NextToken")
        if not token:
            break
    return names


def _delete_rule_and_confirm(xr, rule_name, timeout_s=60):
    """Deletes the rule and polls until GetSamplingRules no longer lists it."""
    xr.delete_sampling_rule(RuleName=rule_name)
    _poll_until(
        lambda: _sampling_rule_names(xr),
        lambda names: rule_name not in names,
        timeout_s=timeout_s,
        interval_s=2,
        description=f"sampling rule {rule_name} absent from GetSamplingRules after delete",
    )


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSamplingTargets echoes the rule's configured FixedRate, reports a LastRuleModification
    no earlier than the rule's ModifiedAt, and in a mixed call returns a target for the known rule
    while listing only the unknown rule in UnprocessedStatistics.
    """
    xr = ctx.client("xray")
    fixed_rate = 0.25
    rule = _default_sampling_rule(
        ctx.unique_name("sim2real-behav-r-"),
        FixedRate=fixed_rate,
        ReservoirSize=4,
        Priority=random.randint(1, 9999),
    )
    rule_name = rule["RuleName"]
    created = xr.create_sampling_rule(
        SamplingRule=rule, Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["SamplingRuleRecord"]
    ctx.on_cleanup(lambda: _delete_rule_and_confirm(xr, rule_name))
    modified_at = created["ModifiedAt"]
    assert created["SamplingRule"]["FixedRate"] == fixed_rate, created

    stats = {
        "RuleName": rule_name,
        "ClientID": _hex(24),          # ClientID is modelled @length(min=24, max=24)
        "Timestamp": datetime.datetime.now(tz=datetime.timezone.utc),
        "RequestCount": 10,
        "SampledCount": 2,
        "BorrowCount": 0,
    }
    resp = xr.get_sampling_targets(SamplingStatisticsDocuments=[stats])
    assert resp.get("UnprocessedStatistics", []) == [], (
        f"statistics for an existing rule must not be unprocessed: {resp!r}"
    )
    targets = resp.get("SamplingTargetDocuments", [])
    assert len(targets) == 1, f"expected exactly one target document, got {targets!r}"
    target = targets[0]
    assert target.get("RuleName") == rule_name, target
    assert target.get("FixedRate") == fixed_rate, (
        f"SamplingTargetDocument must echo the rule's configured FixedRate {fixed_rate}, "
        f"got {target!r}"
    )

    last_mod = resp.get("LastRuleModification")
    assert last_mod is not None, f"LastRuleModification must be populated: {resp!r}"
    # Our CreateSamplingRule is the most recent configuration change in this account, so the
    # service-reported last modification must sit at (or just after) our rule's ModifiedAt.
    # 5s of slack covers second-granularity truncation on the service side.
    assert last_mod >= modified_at - datetime.timedelta(seconds=5), (
        f"LastRuleModification {last_mod!r} predates this rule's ModifiedAt {modified_at!r}"
    )

    ghost = ctx.unique_name("sim2real-behav-nx-")
    mixed = xr.get_sampling_targets(SamplingStatisticsDocuments=[
        stats,
        dict(stats, RuleName=ghost, ClientID=_hex(24)),
    ])
    mixed_targets = {t["RuleName"] for t in mixed.get("SamplingTargetDocuments", [])}
    assert mixed_targets == {rule_name}, (
        f"only the existing rule may yield a target document, got {mixed_targets!r}"
    )
    unprocessed = mixed.get("UnprocessedStatistics", [])
    assert len(unprocessed) == 1, f"expected one unprocessed entry, got {unprocessed!r}"
    assert unprocessed[0].get("RuleName") == ghost, unprocessed[0]
    assert unprocessed[0].get("ErrorCode"), (
        f"unprocessed statistics entry must carry an ErrorCode, got {unprocessed[0]!r}"
    )

    again = xr.get_sampling_targets(SamplingStatisticsDocuments=[dict(stats, ClientID=_hex(24))])
    assert [t["RuleName"] for t in again.get("SamplingTargetDocuments", [])] == [rule_name], again
    assert again["SamplingTargetDocuments"][0].get("FixedRate") == fixed_rate, again


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
