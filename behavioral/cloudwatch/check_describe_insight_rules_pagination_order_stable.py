"""describe-insight-rules-pagination-order-stable."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "describe-insight-rules-pagination-order-stable"
GROUP = "ordering"
SERVICES = ["cloudwatch"]

_NUM_RULES = 12
_PAGE_SIZE = 5
#: Paired sweeps tried before failing. DescribeInsightRules lists every rule in the account, and
#: another client's PutInsightRule or DeleteInsightRules between two pages moves the page
#: boundaries, so a pair is retried while such churn can explain a skipped or duplicated rule.
_SWEEP_ATTEMPTS = 4


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """DescribeInsightRules pagination (MaxResults-driven NextToken pages) preserves a
    stable rule ordering across two independent full traversals, with no duplicate or
    skipped rule among the ones we created."""
    cw = ctx.client("cloudwatch")
    prefix = ctx.unique_name("sim2real-behav-ir-")
    rule_names = [f"{prefix}{i:02d}" for i in range(_NUM_RULES)]

    for name in rule_names:
        cw.put_insight_rule(
            RuleName=name,
            RuleDefinition=_rule_definition(name),
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )
    ctx.on_cleanup(lambda: cw.delete_insight_rules(RuleNames=rule_names))

    for attempt in range(_SWEEP_ATTEMPTS):
        first_pass = _list_our_rules(cw, prefix)
        second_pass = _list_our_rules(cw, prefix)
        if first_pass == second_pass and sorted(first_pass) == sorted(rule_names):
            break
        if attempt + 1 < _SWEEP_ATTEMPTS:
            # Churn lasts longer than one sweep; a pause lets it pass before the next pair.
            time.sleep(5.0)

    assert len(first_pass) == _NUM_RULES, f"expected {_NUM_RULES} of our rules visible, got {len(first_pass)}"
    assert len(set(first_pass)) == len(first_pass), "duplicate rule name within a single pagination sweep"
    assert set(first_pass) == set(rule_names), "some created rules were skipped by pagination"
    assert first_pass == second_pass, "insight rule ordering was not stable across two independent full paginations"

    # The cleanup delete is otherwise unasserted: prove it actually removes the rules, via an
    # independent read, before on_cleanup repeats it as a (documented, idempotent) no-op.
    delete_failures = cw.delete_insight_rules(RuleNames=rule_names).get("Failures", [])
    assert not delete_failures, f"unexpected per-rule delete failures: {delete_failures}"
    after_delete = _list_our_rules(cw, prefix)
    assert after_delete == [], f"deleted rules still visible via DescribeInsightRules: {after_delete}"


def _rule_definition(log_group_hint: str) -> str:
    return json.dumps(
        {
            "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
            "AggregateOn": "Count",
            "Contribution": {"Keys": ["$.ip"], "Filters": []},
            "LogFormat": "JSON",
            "LogGroupNames": [f"/sim2real-behav/{log_group_hint}"],
        }
    )


def _list_our_rules(cw, prefix: str) -> list[str]:
    names: list[str] = []
    kwargs: dict = {"MaxResults": _PAGE_SIZE}
    while True:
        resp = cw.describe_insight_rules(**kwargs)
        for rule in resp.get("InsightRules", []):
            if rule["Name"].startswith(prefix):
                names.append(rule["Name"])
        next_token = resp.get("NextToken")
        if not next_token:
            break
        kwargs["NextToken"] = next_token
    return names


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
