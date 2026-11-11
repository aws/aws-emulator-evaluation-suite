"""deploy-xray-sampling-rule-cfn-applies."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "deploy-xray-sampling-rule-cfn-applies"
GROUP = "deploy"
SERVICES = ["xray"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed AWS::XRay::SamplingRule is honored by GetSamplingTargets: the returned
    FixedRate matches the deployed rate exactly and the ReservoirQuota never exceeds the
    deployed ReservoirSize."""
    xray = ctx.client("xray")
    rule_name = ctx.unique_name("sim2real-cfn-rule-")[:32]
    fixed_rate = 0.07
    reservoir_size = 5

    template = f"""AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Rule:
    Type: AWS::XRay::SamplingRule
    Properties:
      SamplingRule:
        RuleName: "{rule_name}"
        ResourceARN: "*"
        Priority: 9000
        FixedRate: {fixed_rate}
        ReservoirSize: {reservoir_size}
        ServiceName: "*"
        ServiceType: "*"
        Host: "*"
        HTTPMethod: "*"
        URLPath: "*"
        Version: 1
Outputs:
  RuleARN:
    Value: !GetAtt Rule.RuleARN
"""
    outputs = _deploy_cfn(ctx, template)
    assert outputs["RuleARN"].endswith(rule_name), (
        f"expected stack output RuleARN to end with {rule_name!r}, got {outputs['RuleARN']!r}"
    )

    records = xray.get_sampling_rules()["SamplingRuleRecords"]
    deployed = next(
        (r for r in records if r["SamplingRule"]["RuleName"] == rule_name), None
    )
    assert deployed is not None, (
        f"CFN-deployed sampling rule {rule_name!r} not found via GetSamplingRules"
    )
    assert deployed["SamplingRule"]["FixedRate"] == fixed_rate, (
        f"expected FixedRate={fixed_rate!r}, got {deployed['SamplingRule']['FixedRate']!r}"
    )
    assert deployed["SamplingRule"]["ReservoirSize"] == reservoir_size, (
        f"expected ReservoirSize={reservoir_size!r}, got {deployed['SamplingRule']['ReservoirSize']!r}"
    )

    client_id = uuid.uuid4().hex[:24]

    def _get_target():
        stats_doc = {
            "RuleName": rule_name,
            "ClientID": client_id,
            "Timestamp": time.time(),
            "RequestCount": 20,
            "SampledCount": 4,
            "BorrowCount": 0,
        }
        resp = xray.get_sampling_targets(SamplingStatisticsDocuments=[stats_doc])
        assert resp["UnprocessedStatistics"] == [], (
            f"expected no unprocessed statistics for {rule_name!r}, got "
            f"{resp['UnprocessedStatistics']!r}"
        )
        found = next(
            (t for t in resp["SamplingTargetDocuments"] if t["RuleName"] == rule_name), None
        )
        assert found is not None, (
            f"no sampling target document returned for {rule_name!r}: {resp['SamplingTargetDocuments']!r}"
        )
        return found

    # X-Ray only starts handing out a ReservoirQuota once it has seen statistics from a
    # client for this rule, so poll (reporting fresh statistics each time) until it appears.
    target = _poll_until(_get_target, lambda t: "ReservoirQuota" in t, timeout_s=60, interval_s=5)
    assert target["FixedRate"] == fixed_rate, (
        f"expected served target FixedRate={fixed_rate!r}, got {target['FixedRate']!r}"
    )
    assert 0 <= target["ReservoirQuota"] <= reservoir_size, (
        f"expected 0 <= ReservoirQuota <= {reservoir_size}, got {target['ReservoirQuota']!r}"
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


def _deploy_cfn(ctx, template_body: str) -> dict:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-xray-")
    cfn.create_stack(StackName=stack_name, TemplateBody=template_body)
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


def _delete_stack(cfn, stack_name: str) -> None:
    """Teardown: DeleteStack on an already-deleted stack is a no-op and the waiter accepts a
    stack that no longer exists, so any error here is a real teardown failure."""
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
