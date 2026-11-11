"""deploy-sampling-rule-via-cloudformation-active."""
from __future__ import annotations

import json
import random
import time
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "deploy-sampling-rule-via-cloudformation-active"
GROUP = "deploy"
SERVICES = ["xray"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::XRay::SamplingRule is immediately active:
    it shows up in GetSamplingRules with the fields we declared, and
    GetSamplingTargets returns a live allocation for it (not UnprocessedStatistics)."""
    xray = ctx.client("xray")
    # AWS::XRay::SamplingRule RuleName is capped at 32 chars by CloudFormation; ctx.unique_name
    # appends a 12-hex-char suffix, so the prefix itself must stay <= 20 chars.
    rule_name = ctx.unique_name("sim2real-rule-")
    priority = 100 + (abs(hash(rule_name)) % 900)

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "SamplingRule": {
                "Type": "AWS::XRay::SamplingRule",
                "Properties": {
                    "SamplingRule": {
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
                    }
                },
            }
        },
    }
    stack_name = _deploy_cfn_stack(ctx, template)

    rec = _poll_until(
        lambda: _find_sampling_rule(ctx, rule_name),
        lambda rec: rec is not None,
        timeout_s=60.0,
        interval_s=3.0,
    )
    rule = rec["SamplingRule"]
    assert rule["Priority"] == priority, f"expected Priority {priority}, got {rule['Priority']}"
    assert abs(rule["FixedRate"] - 0.05) < 1e-9, f"expected FixedRate 0.05, got {rule['FixedRate']}"
    assert rule["ReservoirSize"] == 1, f"expected ReservoirSize 1, got {rule['ReservoirSize']}"
    assert rule["ServiceName"] == "*", f"expected ServiceName '*', got {rule['ServiceName']!r}"
    assert rule["RuleARN"], "expected a populated RuleARN for the deployed rule"

    client_id = _make_client_id()

    def _get_target():
        stats_doc = {
            "RuleName": rule_name,
            "ClientID": client_id,
            "Timestamp": datetime.now(timezone.utc),
            "RequestCount": 10,
            "SampledCount": 1,
            "BorrowCount": 0,
        }
        resp = xray.get_sampling_targets(SamplingStatisticsDocuments=[stats_doc])
        unprocessed = {d["RuleName"] for d in resp.get("UnprocessedStatistics", [])}
        assert rule_name not in unprocessed, (
            f"CFN-deployed rule was rejected by GetSamplingTargets: {resp.get('UnprocessedStatistics')}"
        )
        docs_by_name = {d["RuleName"]: d for d in resp.get("SamplingTargetDocuments", [])}
        assert rule_name in docs_by_name, "CFN-deployed rule produced no sampling target allocation"
        return docs_by_name[rule_name]

    # X-Ray only starts handing out a ReservoirQuota once it has seen statistics from a
    # client for this rule, so poll (reporting fresh statistics each time) until it appears.
    target = _poll_until(_get_target, lambda t: "ReservoirQuota" in t, timeout_s=60.0, interval_s=5.0)
    assert abs(target["FixedRate"] - 0.05) < 1e-9, (
        f"expected target FixedRate 0.05, got {target['FixedRate']}"
    )
    assert 0 <= target["ReservoirQuota"] <= 1, (
        f"ReservoirQuota {target['ReservoirQuota']} exceeds the deployed ReservoirSize 1"
    )

    _teardown_stack_and_verify_gone(ctx, stack_name, rule_name)


# ===== helpers =====

def _deploy_cfn_stack(ctx, template: dict) -> str:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-xray-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 200})
    return stack_name


def _delete_stack(cfn, stack_name: str) -> None:
    """Teardown: DeleteStack on an already-deleted stack is a no-op and the waiter accepts a
    stack that no longer exists, so any error here is a real teardown failure."""
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 75}
    )


def _teardown_stack_and_verify_gone(ctx, stack_name: str, rule_name: str) -> None:
    """Tear the stack down as part of the graded body (not just best-effort cleanup) so the
    deletion is actually asserted: an independent GetSamplingRules read must no longer find the
    rule once the stack that declared it is gone."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 75}
    )
    stale = _find_sampling_rule(ctx, rule_name)
    assert stale is None, (
        f"sampling rule {rule_name} still present via GetSamplingRules after stack teardown: {stale}"
    )


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
