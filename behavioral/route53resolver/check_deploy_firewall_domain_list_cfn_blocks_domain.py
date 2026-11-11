"""deploy-firewall-domain-list-cfn-blocks-domain."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-firewall-domain-list-cfn-blocks-domain"
GROUP = "deploy"
SERVICES = ["route53resolver"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.82.0.0/16
  DomainList:
    Type: AWS::Route53Resolver::FirewallDomainList
    Properties:
      Name: sim2real-r53r-fdl
      Domains:
        - sim2real-cfn-blocked-domain.test
  RuleGroup:
    Type: AWS::Route53Resolver::FirewallRuleGroup
    Properties:
      Name: sim2real-r53r-frg
      FirewallRules:
        - FirewallDomainListId: !Ref DomainList
          Priority: 100
          Action: BLOCK
          BlockResponse: NODATA
  Association:
    Type: AWS::Route53Resolver::FirewallRuleGroupAssociation
    Properties:
      FirewallRuleGroupId: !Ref RuleGroup
      VpcId: !Ref Vpc
      Priority: 101
      Name: sim2real-r53r-fassoc
Outputs:
  DomainListId:
    Value: !Ref DomainList
  RuleGroupId:
    Value: !GetAtt RuleGroup.Id
  AssociationId:
    Value: !GetAtt Association.Id
"""


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation stack of a FirewallDomainList, rule group, rule and VPC association yields a
    COMPLETE association whose list holds the configured domain, and after stack deletion each
    resource reads back as not found.
    """
    stack_name, outputs = _deploy_cfn(ctx, _TEMPLATE)
    domain_list_id = outputs["DomainListId"]
    rule_group_id = outputs["RuleGroupId"]
    assoc_id = outputs["AssociationId"]

    r53r = ctx.client("route53resolver")
    cfn = ctx.client("cloudformation")

    def _teardown():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )
        for label, resource_id, probe in (
            (
                "domain list",
                domain_list_id,
                lambda: r53r.get_firewall_domain_list(FirewallDomainListId=domain_list_id),
            ),
            (
                "rule group",
                rule_group_id,
                lambda: r53r.get_firewall_rule_group(FirewallRuleGroupId=rule_group_id),
            ),
            (
                "association",
                assoc_id,
                lambda: r53r.get_firewall_rule_group_association(
                    FirewallRuleGroupAssociationId=assoc_id
                ),
            ),
        ):
            code, message = _error_code(probe)
            assert code == "ResourceNotFoundException", (
                f"expected {label} {resource_id} to be gone after stack delete, "
                f"got error code {code!r}"
            )
            # The message ends in a per-request trace id, so everything before it is asserted.
            expected_prefix = f'[RSLVR-02025] Can’t find the resource with ID "{resource_id}". Trace Id: "'
            assert message.startswith(expected_prefix), (
                f"expected message starting {expected_prefix!r}, got {message!r}"
            )

    ctx.on_cleanup(_teardown)

    status = _poll_until(
        lambda: r53r.get_firewall_rule_group_association(
            FirewallRuleGroupAssociationId=assoc_id
        )["FirewallRuleGroupAssociation"]["Status"],
        lambda s: s in ("COMPLETE", "FAILED"),
        timeout_s=90,
        interval_s=5,
    )
    assert status == "COMPLETE", f"association reached {status}, not COMPLETE"

    assoc = r53r.get_firewall_rule_group_association(
        FirewallRuleGroupAssociationId=assoc_id
    )["FirewallRuleGroupAssociation"]
    assert assoc["FirewallRuleGroupId"] == rule_group_id, (
        f"expected association {assoc_id} to reference rule group {rule_group_id}, "
        f"got {assoc['FirewallRuleGroupId']}"
    )

    domain_list_status = _poll_until(
        lambda: r53r.get_firewall_domain_list(FirewallDomainListId=domain_list_id)[
            "FirewallDomainList"
        ]["Status"],
        lambda s: s in ("COMPLETE", "COMPLETE_IMPORT_FAILED"),
        timeout_s=90,
        interval_s=5,
    )
    assert domain_list_status == "COMPLETE", domain_list_status

    domains = r53r.list_firewall_domains(FirewallDomainListId=domain_list_id)["Domains"]
    assert any(
        d.lower().rstrip(".") == "sim2real-cfn-blocked-domain.test" for d in domains
    ), domains

    rule_group = r53r.get_firewall_rule_group(FirewallRuleGroupId=rule_group_id)[
        "FirewallRuleGroup"
    ]
    assert rule_group["Status"] == "COMPLETE", (
        f"expected CFN-deployed rule group {rule_group_id} to be COMPLETE, got {rule_group['Status']}"
    )
    assert rule_group["RuleCount"] == 1, (
        f"expected exactly 1 rule in {rule_group_id}, got RuleCount={rule_group['RuleCount']}"
    )

    rules = r53r.list_firewall_rules(FirewallRuleGroupId=rule_group_id)["FirewallRules"]
    assert len(rules) == 1, f"expected exactly 1 rule listed for {rule_group_id}, got {rules}"
    assert rules[0]["Action"] == "BLOCK", f"expected the CFN-deployed rule to BLOCK, got {rules[0]}"
    assert rules[0]["FirewallDomainListId"] == domain_list_id, (
        f"expected rule to reference domain list {domain_list_id}, got {rules[0]['FirewallDomainListId']}"
    )


def _deploy_cfn(ctx, template_body: str) -> tuple[str, dict]:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-r53r-fw-stack-")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    return stack_name, {o["OutputKey"]: o["OutputValue"] for o in outputs}


def _error_code(fn):
    """Call fn(), which AWS refuses; return the botocore Error (Code, Message) of its ClientError."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message", "")
    raise AssertionError("the call succeeded; expected AWS to refuse it with a ClientError")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = probe()
    if not predicate(value):
        raise AssertionError(f"condition not met within {timeout_s}s (last value: {value!r})")
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
