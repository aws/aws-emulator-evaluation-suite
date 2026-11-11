"""obs-dynamodb-2-contributor-insights-hot-key-closed-loop."""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-dynamodb-2-contributor-insights-hot-key-closed-loop"
GROUP = "contributor-insights"
SERVICES = ["cloudwatch", "dynamodb"]

_HOT = "hot"
_HOT_READS = 90
_COLD_KEYS = [f"cold{i:02d}" for i in range(10)]   # 10 reads, one per other partition key
_POST_DISABLE_READS = 30
#: The rule NAME is DynamoDB-minted, following the convention
#:   DynamoDBContributorInsights-<PKC|PKT>-<TableName>-<epoch-millis>
#: PKC = most-accessed partition keys (ValueOf ConsumedThroughputUnits), PKT = most-throttled
#: (ValueOf ThrottleCount); both share one epoch suffix. A hash-only table gets no SKC/SKT. Mode
#: THROTTLED_KEYS creates PKT only. DISABLE deletes the rules, after which GetInsightRuleReport on
#: the old name is refused InvalidParameterValue. Traffic in the first ~2-3 min after ENABLED is
#: not reflected in the report, so a warm-up key is driven until it appears before the measured
#: burst. A consistent GetItem of a small item is 1.0 RCU, so a key's Sum equals its read count.
#: Writes also feed PKC, so every item is seeded BEFORE enabling.
_RULE_RE = r"^DynamoDBContributorInsights-(PKC|PKT|SKC|SKT)-{table}-(\d+)$"
_ENABLE_TIMEOUT_S = 180
_WARMUP_TIMEOUT_S = 600
_REPORT_TIMEOUT_S = 900
_BARRIER_TIMEOUT_S = 600
_POLL_S = 2
#: One warm-up read per this many seconds keeps the warm-up key's Sum well below the hot key's.
_WARMUP_READ_S = 15


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _error(fn):
    """(code, message) of a call real AWS refuses. RAISES if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused; it succeeded: {result!r}")


def _await_ci(ddb, table, want, timeout_s, ctx=None):
    """Poll DescribeContributorInsights until its status == want; return the description."""
    deadline = time.monotonic() + timeout_s
    while True:
        d = ddb.describe_contributor_insights(TableName=table)
        if d["ContributorInsightsStatus"] == want:
            return d
        assert d["ContributorInsightsStatus"] != "FAILED", f"CI on {table!r} FAILED: {d!r}"
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"contributor insights on {table!r} to reach {want!r}: the run "
                                   f"budget ended first; not graded")
            raise AssertionError(
                f"contributor insights on {table!r} never reached {want!r} within {timeout_s:.0f}s; "
                f"last {d['ContributorInsightsStatus']!r}")
        time.sleep(_POLL_S)


def _rules_for(cw, table):
    """{rule name: rule} for every insight rule named for `table`, paginated."""
    pat = re.compile(_RULE_RE.format(table=re.escape(table)))
    out, token = {}, None
    while True:
        page = cw.describe_insight_rules(**({"NextToken": token} if token else {}))
        for r in page["InsightRules"]:
            if f"-{table}-" in r["Name"]:
                assert pat.match(r["Name"]), (
                    f"insight rule {r['Name']!r} names table {table!r} but does not follow "
                    f"DynamoDBContributorInsights-<PKC|PKT|SKC|SKT>-<table>-<millis>")
                out[r["Name"]] = r
        token = page.get("NextToken")
        if not token:
            return out


def _contributors(cw, rule, start):
    """[(partition key, aggregate value)] of a rule's report since `start`, in returned order."""
    rep = cw.get_insight_rule_report(
        RuleName=rule, StartTime=start, EndTime=datetime.now(timezone.utc) + timedelta(minutes=1),
        Period=60, MaxContributorCount=20, OrderBy="Sum")
    assert rep.get("KeyLabels") == ["PartitionKey"], f"{rule!r} KeyLabels {rep.get('KeyLabels')!r}"
    return [(c["Keys"][0], c["ApproximateAggregateValue"]) for c in rep["Contributors"]]


def _read(ddb, table, pk, n=1):
    for _ in range(n):
        ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True)


def _make_table(ctx, ddb, name):
    ddb.create_table(
        TableName=name, BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))


def _enable(ctx, ddb, table, mode):
    resp = ddb.update_contributor_insights(
        TableName=table, ContributorInsightsAction="ENABLE", ContributorInsightsMode=mode)
    ctx.on_cleanup(lambda: ddb.update_contributor_insights(
        TableName=table, ContributorInsightsAction="DISABLE"))
    assert resp["ContributorInsightsStatus"] == "ENABLING", (
        f"ENABLE on {table!r} returned status {resp['ContributorInsightsStatus']!r}")
    assert resp.get("ContributorInsightsMode") == mode, (
        f"ENABLE on {table!r} echoed mode {resp.get('ContributorInsightsMode')!r}, sent {mode!r}")


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_GetInsightRuleReport.html
@tags("concern:data-plane", "concern:metrics", "dp:api", "plane:data", "axis:happy-path", "cap:c1", "timing:real-time")
def run(ctx) -> None:
    """ACCESSED_AND_THROTTLED_KEYS mints PKC+PKT rules (THROTTLED_KEYS only PKT); 90 hot reads rank
    first at Sum 90 with ten cold keys at 1 each; DISABLE deletes the rules so later reads accrue
    nowhere, while a still-enabled control table proves those later reads were delivered.
    """
    ddb = ctx.client("dynamodb")
    cw = ctx.client("cloudwatch")
    table = ctx.unique_name("sim2real-xsvc-ci-a-")
    twin = ctx.unique_name("sim2real-xsvc-ci-t-")
    control = ctx.unique_name("sim2real-xsvc-ci-c-")

    for name in (table, twin, control):
        _make_table(ctx, ddb, name)
    for name in (table, twin, control):
        ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # Seed every key BEFORE enabling: PKC counts write units too, so seeding later would skew sums.
    for pk in [_HOT, "warmup", "post", *_COLD_KEYS]:
        for name in (table, control):
            ddb.put_item(TableName=name, Item={"pk": {"S": pk}, "v": {"S": "x" * 16}})

    _enable(ctx, ddb, table, "ACCESSED_AND_THROTTLED_KEYS")
    _enable(ctx, ddb, twin, "THROTTLED_KEYS")
    _enable(ctx, ddb, control, "ACCESSED_AND_THROTTLED_KEYS")
    desc = {n: _await_ci(ddb, n, "ENABLED", _budget_s(ctx, _ENABLE_TIMEOUT_S), ctx=ctx) for n in (table, twin, control)}

    # --- rule naming: DynamoDB-minted, listed by CloudWatch, agreeing across both services ----
    rules = {n: _rules_for(cw, n) for n in (table, twin, control)}
    for n in (table, twin, control):
        listed = set(desc[n].get("ContributorInsightsRuleList", []))
        assert listed == set(rules[n]), (
            f"{n!r}: DynamoDB lists rules {sorted(listed)!r} but CloudWatch "
            f"DescribeInsightRules lists {sorted(rules[n])!r}")
    kinds = {n: sorted(re.match(_RULE_RE.format(table=re.escape(n)), r).group(1)
                       for r in rules[n]) for n in (table, twin, control)}
    assert kinds[table] == ["PKC", "PKT"], (
        f"ACCESSED_AND_THROTTLED_KEYS on a hash-only table minted {kinds[table]!r}, "
        f"expected PKC + PKT")
    assert kinds[twin] == ["PKT"], (
        f"THROTTLED_KEYS twin minted {kinds[twin]!r}; the accessed-keys PKC rule must be absent")
    suffixes = {re.match(_RULE_RE.format(table=re.escape(table)), r).group(2) for r in rules[table]}
    assert len(suffixes) == 1, f"PKC/PKT of one enable carry different suffixes {suffixes!r}"
    for name, r in rules[table].items():
        assert r["State"] == "ENABLED", f"rule {name!r} state {r['State']!r}"
        defn = json.loads(r["Definition"])
        want_value = "ConsumedThroughputUnits" if "-PKC-" in name else "ThrottleCount"
        assert defn["Contribution"]["ValueOf"] == want_value, (
            f"rule {name!r} aggregates {defn['Contribution']['ValueOf']!r}, expected {want_value!r}")
        assert defn["Contribution"]["Keys"] == ["PartitionKey"], (
            f"rule {name!r} keys {defn['Contribution']['Keys']!r}")
        assert defn.get("TableName") == table, f"rule {name!r} TableName {defn.get('TableName')!r}"
    twin_pkt = next(iter(rules[twin]))
    assert json.loads(rules[twin][twin_pkt]["Definition"])["Contribution"]["ValueOf"] == (
        "ThrottleCount"), f"twin's only rule {twin_pkt!r} is not a throttle-count rule"
    pkc = next(r for r in rules[table] if "-PKC-" in r)
    control_pkc = next(r for r in rules[control] if "-PKC-" in r)

    # --- warm-up barrier: ingestion is live once a read of 'warmup' appears in both reports ---
    start = datetime.now(timezone.utc) - timedelta(minutes=1)
    warmup_s = _budget_s(ctx, _WARMUP_TIMEOUT_S)
    deadline = time.monotonic() + warmup_s
    last_read = None
    while True:
        if last_read is None or time.monotonic() - last_read >= _WARMUP_READ_S:
            _read(ddb, table, "warmup")
            _read(ddb, control, "warmup")
            last_read = time.monotonic()
        live = [dict(_contributors(cw, r, start)).get("warmup") for r in (pkc, control_pkc)]
        if all(live):
            break
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError("a warm-up read in the PKC reports: the run budget ended first; "
                                   "not graded")
            raise AssertionError(
                f"no warm-up read surfaced in the PKC reports within {warmup_s:.0f}s; "
                f"warmup values (table, control) = {live!r}")
        time.sleep(_POLL_S)

    # --- the measured burst: 90 reads on one key, 10 spread across ten others ----------------
    _read(ddb, table, _HOT, _HOT_READS)
    for pk in _COLD_KEYS:
        _read(ddb, table, pk)

    report_s = _budget_s(ctx, _REPORT_TIMEOUT_S)
    deadline = time.monotonic() + report_s
    while True:
        ranked = _contributors(cw, pkc, start)
        got = dict(ranked)
        if got.get(_HOT, 0) >= _HOT_READS and all(got.get(k, 0) >= 1 for k in _COLD_KEYS):
            break
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"the PKC report for {table!r} to show the burst: the run budget "
                                   f"ended first; not graded")
            raise AssertionError(
                f"PKC report for {table!r} never showed {_HOT!r}>={_HOT_READS} and all ten cold "
                f"keys within {report_s:.0f}s; last ranking {ranked!r}")
        time.sleep(_POLL_S)

    assert ranked[0][0] == _HOT, f"top contributor is {ranked[0]!r}, expected {_HOT!r}: {ranked!r}"
    assert got[_HOT] == float(_HOT_READS), (
        f"{_HOT!r} aggregated {got[_HOT]!r} consumed units; {_HOT_READS} consistent 1-RCU reads "
        f"should sum to {float(_HOT_READS)!r}")
    cold = {k: got[k] for k in _COLD_KEYS}
    assert all(v == 1.0 for v in cold.values()), f"cold keys should each be 1.0: {cold!r}"
    values = [v for _, v in ranked]
    assert values == sorted(values, reverse=True), f"Contributors not ordered by Sum desc: {ranked!r}"
    assert set(got) == {_HOT, "warmup", *_COLD_KEYS}, (
        f"report contributors {sorted(got)!r} include keys this check never read")

    # --- DISABLE: the rules are deleted, so later reads have nowhere to accrue ----------------
    off = ddb.update_contributor_insights(TableName=table, ContributorInsightsAction="DISABLE")
    assert off["ContributorInsightsStatus"] == "DISABLING", f"DISABLE returned {off!r}"
    gone = _await_ci(ddb, table, "DISABLED", _budget_s(ctx, _ENABLE_TIMEOUT_S), ctx=ctx)
    assert not gone.get("ContributorInsightsRuleList"), (
        f"DISABLED table still lists rules {gone.get('ContributorInsightsRuleList')!r}")

    # Differential barrier: the same post-disable reads go to the disabled table and the control.
    _read(ddb, table, _HOT, _POST_DISABLE_READS)
    _read(ddb, control, "post", _POST_DISABLE_READS)
    barrier_s = _budget_s(ctx, _BARRIER_TIMEOUT_S)
    deadline = time.monotonic() + barrier_s
    while True:
        ctl = dict(_contributors(cw, control_pkc, start)).get("post", 0)
        if ctl >= _POST_DISABLE_READS:
            break
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError("the control table's PKC to show the post reads: the run budget "
                                   "ended first; not graded")
            raise AssertionError(
                f"control table's PKC never showed the {_POST_DISABLE_READS} post reads within "
                f"{barrier_s:.0f}s (saw {ctl!r}); the barrier never closed")
        time.sleep(_POLL_S)
    assert ctl == float(_POST_DISABLE_READS), f"control 'post' aggregated {ctl!r}"

    leftover = _rules_for(cw, table)
    assert leftover == {}, f"after DISABLE, rules for {table!r} still exist: {sorted(leftover)!r}"
    code, message = _error(lambda: _contributors(cw, pkc, start))
    assert code == "InvalidParameterValue", (
        f"GetInsightRuleReport on the deleted rule {pkc!r} raised {code!r}, "
        f"expected 'InvalidParameterValue'")
    assert message == f"RULE_NAME: {pkc}", (
        f"GetInsightRuleReport on the deleted rule {pkc!r} said {message!r}, "
        f"expected {f'RULE_NAME: {pkc}'!r}")
    assert sorted(_rules_for(cw, control)) == sorted(rules[control]), (
        "the control table's rules changed while only the measured table was disabled")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
