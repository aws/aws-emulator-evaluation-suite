"""deploy-ses-receipt-rule-set-cfn-activatable."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "deploy-ses-receipt-rule-set-cfn-activatable"
GROUP = "deploy"
SERVICES = ["ses"]

_TEMPLATE_BODY = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  RuleSetNameParam:
    Type: String
  RuleNameParam:
    Type: String
Resources:
  RuleSet:
    Type: AWS::SES::ReceiptRuleSet
    Properties:
      RuleSetName: !Ref RuleSetNameParam
  Rule:
    Type: AWS::SES::ReceiptRule
    DependsOn: RuleSet
    Properties:
      RuleSetName: !Ref RuleSetNameParam
      Rule:
        Name: !Ref RuleNameParam
        Enabled: true
        ScanEnabled: false
        Actions:
          - StopAction:
              Scope: RuleSet
"""


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control", "resource:account-singleton:ses-active-receipt-rule-set")
def run(ctx) -> None:
    """A receipt rule set and rule deployed via CloudFormation are genuinely present
    in DescribeReceiptRuleSet (not merely recorded in the CFN stack), and the rule set
    can actually be made the account's active receipt rule set."""
    ses = ctx.client("ses")
    rule_set_name = ctx.unique_name("sim2real-ses-cfnrs-")
    rule_name = ctx.unique_name("sim2real-ses-cfnrule-")
    _deploy_cfn(
        ctx,
        _TEMPLATE_BODY,
        {"RuleSetNameParam": rule_set_name, "RuleNameParam": rule_name},
    )

    desc = ses.describe_receipt_rule_set(RuleSetName=rule_set_name)
    assert desc["Metadata"]["Name"] == rule_set_name, (
        f"expected DescribeReceiptRuleSet to echo {rule_set_name!r}, got {desc['Metadata']!r}"
    )
    rule_names = [r["Name"] for r in desc["Rules"]]
    assert rule_name in rule_names, (
        f"expected {rule_name!r} among the CFN-deployed rules, got {rule_names!r}"
    )
    deployed_rule = next(r for r in desc["Rules"] if r["Name"] == rule_name)
    assert deployed_rule["Enabled"] is True, (
        f"expected the CFN-deployed rule to be enabled, got Enabled={deployed_rule['Enabled']!r}"
    )

    previous_active = _active_rule_set_name(ses)
    ses.set_active_receipt_rule_set(RuleSetName=rule_set_name)

    def _restore_active() -> None:
        if previous_active:
            ses.set_active_receipt_rule_set(RuleSetName=previous_active)
        else:
            ses.set_active_receipt_rule_set()

    ctx.on_cleanup(_restore_active)

    active = ses.describe_active_receipt_rule_set()
    assert active["Metadata"]["Name"] == rule_set_name, (
        f"expected {rule_set_name!r} to be the active rule set, got {active['Metadata']!r}"
    )
    active_rule_names = [r["Name"] for r in active["Rules"]]
    assert rule_name in active_rule_names, (
        f"expected {rule_name!r} among the active rule set's rules, got {active_rule_names!r}"
    )

    # De-activate before the stack teardown tries to delete the rule set, since SES
    # rejects deleting the currently-active rule set.
    _restore_active()


def _active_rule_set_name(ses: Any) -> str | None:
    resp = ses.describe_active_receipt_rule_set()
    metadata = resp.get("Metadata") or {}
    return metadata.get("Name")


def _deploy_cfn(ctx: Any, template_body: str, parameters: dict[str, str]) -> str:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-ses-stack-")

    def _cleanup() -> None:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=[
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ],
    )
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    return stack_name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
