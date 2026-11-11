"""deploy-resolver-rule-cfn-forwards-queries."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-resolver-rule-cfn-forwards-queries"
GROUP = "deploy"
SERVICES = ["route53resolver"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.81.0.0/16
      Tags:
        - Key: sim2real
          Value: "true"
  SubnetA:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.81.1.0/24
      AvailabilityZone: !Select [0, !GetAZs '']
      Tags:
        - Key: sim2real
          Value: "true"
  SubnetB:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.81.2.0/24
      AvailabilityZone: !Select [1, !GetAZs '']
      Tags:
        - Key: sim2real
          Value: "true"
  Sg:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: sim2real resolver outbound sg
      VpcId: !Ref Vpc
      Tags:
        - Key: sim2real
          Value: "true"
  OutboundEndpoint:
    Type: AWS::Route53Resolver::ResolverEndpoint
    Properties:
      Direction: OUTBOUND
      IpAddresses:
        - SubnetId: !Ref SubnetA
        - SubnetId: !Ref SubnetB
      SecurityGroupIds: [!Ref Sg]
      Name: sim2real-r53r-cfn-ep
      Tags:
        - Key: sim2real
          Value: "true"
  Rule:
    Type: AWS::Route53Resolver::ResolverRule
    Properties:
      DomainName: sim2real-cfn-forward.test.
      RuleType: FORWARD
      ResolverEndpointId: !Ref OutboundEndpoint
      TargetIps:
        - Ip: 10.254.254.254
          Port: 53
      Name: sim2real-r53r-cfn-rule
      Tags:
        - Key: sim2real
          Value: "true"
  RuleAssociation:
    Type: AWS::Route53Resolver::ResolverRuleAssociation
    Properties:
      ResolverRuleId: !Ref Rule
      VPCId: !Ref Vpc
Outputs:
  RuleId:
    Value: !Ref Rule
  AssociationId:
    Value: !Ref RuleAssociation
  VpcId:
    Value: !Ref Vpc
"""


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A ResolverRule and VPC association deployed via CloudFormation reach COMPLETE with the
    association referencing the right rule and VPC, not merely CREATE_COMPLETE on the stack."""
    stack_name, outputs = _deploy_cfn(ctx, _TEMPLATE)
    rule_id = outputs["RuleId"]
    assoc_id = outputs["AssociationId"]
    vpc_id = outputs["VpcId"]

    r53r = ctx.client("route53resolver")
    cfn = ctx.client("cloudformation")

    def _teardown():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 420}
        )
        rule_gone, rule_message = _error_code(lambda: r53r.get_resolver_rule(ResolverRuleId=rule_id))
        assert rule_gone == "ResourceNotFoundException", (
            f"rule {rule_id} still answers GetResolverRule after stack deletion: {rule_gone!r}"
        )
        expected = f'[RSLVR-00703] Resolver rule with ID "{rule_id}" does not exist.'
        assert rule_message == expected, f"expected message {expected!r}, got {rule_message!r}"
        assoc_gone, assoc_message = _error_code(
            lambda: r53r.get_resolver_rule_association(ResolverRuleAssociationId=assoc_id)
        )
        assert assoc_gone == "ResourceNotFoundException", (
            f"association {assoc_id} still answers GetResolverRuleAssociation after stack "
            f"deletion: {assoc_gone!r}"
        )
        expected = f'ResolverRuleAssociation "{assoc_id}" does not Exist.'
        assert assoc_message == expected, f"expected message {expected!r}, got {assoc_message!r}"

    ctx.on_cleanup(_teardown)

    status = _poll_until(
        lambda: r53r.get_resolver_rule_association(ResolverRuleAssociationId=assoc_id)[
            "ResolverRuleAssociation"
        ]["Status"],
        lambda s: s in ("COMPLETE", "FAILED"),
        timeout_s=120,
        interval_s=5,
    )
    assert status == "COMPLETE", f"association reached terminal status {status}, not COMPLETE"

    assoc = r53r.get_resolver_rule_association(ResolverRuleAssociationId=assoc_id)[
        "ResolverRuleAssociation"
    ]
    assert assoc["ResolverRuleId"] == rule_id, (
        f"association {assoc_id} references rule {assoc['ResolverRuleId']!r}, expected {rule_id!r}"
    )
    assert assoc["VPCId"] == vpc_id, (
        f"association {assoc_id} references VPC {assoc['VPCId']!r}, expected {vpc_id!r}"
    )

    rule = r53r.get_resolver_rule(ResolverRuleId=rule_id)["ResolverRule"]
    assert rule["Status"] == "COMPLETE", f"rule {rule_id} reached status {rule['Status']!r}, not COMPLETE"
    assert rule["DomainName"].rstrip(".").lower() == "sim2real-cfn-forward.test", (
        f"rule {rule_id} has domain {rule['DomainName']!r}, expected sim2real-cfn-forward.test"
    )


# ===== helpers =====

def _deploy_cfn(ctx, template_body: str) -> tuple[str, dict]:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-r53r-stack-")

    cfn.create_stack(StackName=stack_name, TemplateBody=template_body)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 600}
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
    while not predicate(value):
        assert time.monotonic() < deadline, f"condition not met within {timeout_s}s, last={value!r}"
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
