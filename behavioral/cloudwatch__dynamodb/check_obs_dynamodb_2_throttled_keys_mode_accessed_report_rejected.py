"""obs-dynamodb-2-throttled-keys-mode-accessed-report-rejected."""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-dynamodb-2-throttled-keys-mode-accessed-report-rejected"
GROUP = "contributor-insights-rejected"
SERVICES = ["cloudwatch", "dynamodb"]

#: Rule names are DynamoDBContributorInsights-<PKC|PKT>-<table>-<ms>,
#: with PKC and PKT of one enable sharing the suffix. THROTTLED_KEYS mints PKT only, and
#: GetInsightRuleReport on a rule name that does not exist is refused InvalidParameterValue.
_RULE_RE = r"^DynamoDBContributorInsights-(PKC|PKT|SKC|SKT)-{table}-(\d+)$"
_ENABLE_TIMEOUT_S = 180


def _error(fn):
    """Error code of a call real AWS refuses. RAISES if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused; it succeeded: {result!r}")


def _await_ci(ddb, table, want, timeout_s):
    deadline = time.monotonic() + timeout_s
    while True:
        d = ddb.describe_contributor_insights(TableName=table)
        if d["ContributorInsightsStatus"] == want:
            return d
        assert d["ContributorInsightsStatus"] != "FAILED", f"CI on {table!r} FAILED: {d!r}"
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"contributor insights on {table!r} never reached {want!r} within {timeout_s}s; "
                f"last {d['ContributorInsightsStatus']!r}")
        time.sleep(5)


def _rules_for(cw, table):
    """{rule name: rule} for every insight rule named for `table`, paginated."""
    out, token = {}, None
    while True:
        page = cw.describe_insight_rules(**({"NextToken": token} if token else {}))
        out.update({r["Name"]: r for r in page["InsightRules"] if f"-{table}-" in r["Name"]})
        token = page.get("NextToken")
        if not token:
            return out


def _report(cw, rule):
    now = datetime.now(timezone.utc)
    return cw.get_insight_rule_report(
        RuleName=rule, StartTime=now - timedelta(minutes=10), EndTime=now + timedelta(minutes=1),
        Period=60, MaxContributorCount=10, OrderBy="Sum")


@tags("axis:rejection", "concern:metrics", "concern:negative-classes", "cap:c1", "plane:control")
def run(ctx) -> None:
    """THROTTLED_KEYS mode mints only the PKT rule, so a report on its PKC sibling name is refused
    InvalidParameterValue, while the minted PKT rule reports normally and stays ENABLED.
    """
    ddb = ctx.client("dynamodb")
    cw = ctx.client("cloudwatch")
    table = ctx.unique_name("sim2real-xsvc-ci-n-")

    ddb.create_table(
        TableName=table, BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    resp = ddb.update_contributor_insights(
        TableName=table, ContributorInsightsAction="ENABLE",
        ContributorInsightsMode="THROTTLED_KEYS")
    ctx.on_cleanup(lambda: ddb.update_contributor_insights(
        TableName=table, ContributorInsightsAction="DISABLE"))
    assert resp.get("ContributorInsightsMode") == "THROTTLED_KEYS", f"ENABLE echoed {resp!r}"
    desc = _await_ci(ddb, table, "ENABLED", _ENABLE_TIMEOUT_S)
    assert desc.get("ContributorInsightsMode") == "THROTTLED_KEYS", (
        f"described mode {desc.get('ContributorInsightsMode')!r}")

    rules = _rules_for(cw, table)
    assert set(rules) == set(desc.get("ContributorInsightsRuleList", [])), (
        f"CloudWatch lists {sorted(rules)!r}, DynamoDB lists "
        f"{desc.get('ContributorInsightsRuleList')!r}")
    assert len(rules) == 1, f"THROTTLED_KEYS on a hash-only table minted {sorted(rules)!r}"
    pkt = next(iter(rules))
    m = re.match(_RULE_RE.format(table=re.escape(table)), pkt)
    assert m and m.group(1) == "PKT", f"the only rule {pkt!r} is not a PKT rule for {table!r}"
    assert json.loads(rules[pkt]["Definition"])["Contribution"]["ValueOf"] == "ThrottleCount", (
        f"PKT rule definition {rules[pkt]['Definition']!r}")

    # --- positive control: the minted throttled-keys rule reports ---------------------------
    ok = _report(cw, pkt)
    assert ok["KeyLabels"] == ["PartitionKey"], f"PKT report KeyLabels {ok['KeyLabels']!r}"
    assert ok["AggregationStatistic"] == "Sum", f"PKT report statistic {ok['AggregationStatistic']!r}"

    # --- break exactly one thing: ask for the accessed-keys sibling this mode never minted ----
    pkc = pkt.replace("-PKT-", "-PKC-", 1)
    got = _error(lambda: _report(cw, pkc))
    want = ("InvalidParameterValue", f"RULE_NAME: {pkc}")
    assert got == want, (
        f"GetInsightRuleReport on the never-minted accessed-keys rule {pkc!r} raised {got!r}, "
        f"expected {want!r}")

    # --- effect absent: still no PKC rule, and the PKT rule is unaffected by the refusal ------
    after = _rules_for(cw, table)
    assert sorted(after) == [pkt], f"rules for {table!r} after the refusal: {sorted(after)!r}"
    assert after[pkt]["State"] == "ENABLED", f"PKT rule state {after[pkt]['State']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
