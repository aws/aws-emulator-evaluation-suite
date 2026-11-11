"""deploy-xray-sampling-rule-cfn-then-serves-targets."""
from __future__ import annotations

import json
import random
import time

from behavioral_harness import tags

CHECK = "deploy-xray-sampling-rule-cfn-then-serves-targets"
GROUP = "deploy"
SERVICES = ["xray"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An AWS::XRay::SamplingRule deployed via CloudFormation reads back its FixedRate,
    ReservoirSize and Priority, and GetSamplingTargets serves a target with that FixedRate."""
    cfn = ctx.client("cloudformation")
    xray = ctx.client("xray")

    rule_name = ctx.unique_name("sim2real-rule-")[:32]
    priority = random.randint(100, 9000)
    fixed_rate = 0.31
    reservoir_size = 7
    stack_name = ctx.unique_name("sim2ray-xray-rule-")

    template = json.dumps(
        {
            "Resources": {
                "Rule": {
                    "Type": "AWS::XRay::SamplingRule",
                    "Properties": {
                        "SamplingRule": {
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
                        }
                    },
                }
            },
            "Outputs": {"RuleArn": {"Value": {"Ref": "Rule"}}},
        }
    )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Tags=[{"Key": "owner", "Value": "fidelity"}],
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))

    stack = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0],
        lambda s: s["StackStatus"] in ("CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"),
        timeout_s=180,
        interval_s=5,
    )
    assert stack["StackStatus"] == "CREATE_COMPLETE", stack.get("StackStatusReason")

    record = _find_rule(xray, rule_name)
    assert record is not None, "template-defined sampling rule not found via GetSamplingRules"
    rule = record["SamplingRule"]
    assert rule["FixedRate"] == fixed_rate, f"expected FixedRate={fixed_rate}, got {rule['FixedRate']}"
    assert rule["ReservoirSize"] == reservoir_size, (
        f"expected ReservoirSize={reservoir_size}, got {rule['ReservoirSize']}"
    )
    assert rule["Priority"] == priority, f"expected Priority={priority}, got {rule['Priority']}"

    stats_doc = {
        "RuleName": rule_name,
        "ClientID": _hex(24),
        "Timestamp": time.time(),
        "RequestCount": 10,
        "SampledCount": 5,
        "BorrowCount": 0,
    }
    targets = xray.get_sampling_targets(SamplingStatisticsDocuments=[stats_doc])
    unprocessed = targets.get("UnprocessedStatistics", [])
    assert unprocessed == [], f"expected no unprocessed statistics, got {unprocessed}"
    target = next(
        (t for t in targets["SamplingTargetDocuments"] if t["RuleName"] == rule_name), None
    )
    assert target is not None, f"no sampling target served for {rule_name}: {targets}"
    assert target["FixedRate"] == fixed_rate, (
        f"expected served FixedRate={fixed_rate}, got {target['FixedRate']}"
    )


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
