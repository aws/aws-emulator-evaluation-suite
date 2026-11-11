"""deploy-resolver-endpoint-cfn-behaves."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-resolver-endpoint-cfn-behaves"
GROUP = "state-machine"
SERVICES = ["route53resolver"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  SubnetId1:
    Type: String
  SubnetId2:
    Type: String
  SecurityGroupId:
    Type: String
  EndpointName:
    Type: String
Resources:
  ResolverEndpoint:
    Type: AWS::Route53Resolver::ResolverEndpoint
    Properties:
      Direction: OUTBOUND
      Name: !Ref EndpointName
      IpAddresses:
        - SubnetId: !Ref SubnetId1
        - SubnetId: !Ref SubnetId2
      SecurityGroupIds:
        - !Ref SecurityGroupId
Outputs:
  ResolverEndpointId:
    Value: !Ref ResolverEndpoint
"""


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A ResolverEndpoint deployed through CloudFormation reaches OPERATIONAL and is usable: a
    ResolverRule on it can be created and associated with a VPC, not just CREATE_COMPLETE."""
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    r53r = ctx.client("route53resolver")

    vpc_id, subnet_ids, sg_id = _create_networking(ctx, ec2)

    stack_name = ctx.unique_name("sim2real-r53r-cfn-")
    endpoint_name = ctx.unique_name("sim2real-endpoint-")[:64]
    outputs = _deploy_cfn(
        ctx,
        cfn,
        stack_name,
        _TEMPLATE,
        [
            {"ParameterKey": "SubnetId1", "ParameterValue": subnet_ids[0]},
            {"ParameterKey": "SubnetId2", "ParameterValue": subnet_ids[1]},
            {"ParameterKey": "SecurityGroupId", "ParameterValue": sg_id},
            {"ParameterKey": "EndpointName", "ParameterValue": endpoint_name},
        ],
    )
    endpoint_id = outputs["ResolverEndpointId"]

    endpoint = _poll_until(
        lambda: r53r.get_resolver_endpoint(ResolverEndpointId=endpoint_id)["ResolverEndpoint"],
        lambda e: e["Status"] in ("OPERATIONAL", "ACTION_NEEDED"),
        timeout_s=300,
        interval_s=5,
    )
    assert endpoint["Status"] == "OPERATIONAL", f"expected OPERATIONAL, got {endpoint['Status']!r}"

    rule_id = r53r.create_resolver_rule(
        CreatorRequestId=ctx.unique_name("sim2real-r53r-crr-"),
        Name=ctx.unique_name("sim2real-rule-")[:64],
        RuleType="FORWARD",
        DomainName="sim2real-r53r-cfn-e2e.example.",
        TargetIps=[{"Ip": "192.0.2.1", "Port": 53}],
        ResolverEndpointId=endpoint_id,
    )["ResolverRule"]["Id"]
    ctx.on_cleanup(lambda: _safe_delete_rule(r53r, rule_id))

    assoc = r53r.associate_resolver_rule(ResolverRuleId=rule_id, VPCId=vpc_id)["ResolverRuleAssociation"]
    assoc_id = assoc["Id"]
    ctx.on_cleanup(lambda: _safe_disassociate(r53r, rule_id, vpc_id, assoc_id))

    final = _poll_until(
        lambda: r53r.get_resolver_rule_association(ResolverRuleAssociationId=assoc_id)["ResolverRuleAssociation"],
        lambda a: a["Status"] in ("COMPLETE", "OVERRIDDEN", "FAILED"),
        timeout_s=180,
        interval_s=5,
    )
    assert final["Status"] in ("COMPLETE", "OVERRIDDEN"), (
        f"rule referencing the CFN-deployed endpoint could not be associated: {final}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


def _create_networking(ctx, ec2):
    name = ctx.unique_name("sim2real-r53r-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.0.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_in_use(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.0.{i + 1}.0/24",
            AvailabilityZone=az["ZoneName"],
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": f"{name}-subnet-{i}"}]}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_in_use(lambda: ec2.delete_subnet(SubnetId=sid)))
        subnet_ids.append(subnet_id)

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-r53r-sg-"),
        Description="sim2real route53resolver behavioral check",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": f"{name}-sg"}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_in_use(lambda: ec2.delete_security_group(GroupId=sg_id)))

    return vpc_id, subnet_ids, sg_id


def _deploy_cfn(ctx, cfn, stack_name, template_body, parameters):
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=parameters,
        OnFailure="DELETE",
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _delete_stack(cfn, stack_name):
    try:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )
    except ClientError as e:
        if e.response["Error"]["Code"] != "ValidationError":
            raise


def _delete_in_use(fn, timeout_s=300):
    """Retry a network delete on DependencyViolation while the endpoint's ENIs are released;
    raise at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _safe_delete_rule(r53r, rule_id, timeout_s=180):
    """A rule refuses deletion while an association is still being removed; retry on that refusal."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            r53r.delete_resolver_rule(ResolverRuleId=rule_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _safe_disassociate(r53r, rule_id, vpc_id, assoc_id, timeout_s=180):
    """Disassociate, then wait until the association is gone: the rule and the endpoint behind it
    cannot be deleted while it is still being removed."""
    try:
        r53r.disassociate_resolver_rule(VPCId=vpc_id, ResolverRuleId=rule_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            last = r53r.get_resolver_rule_association(ResolverRuleAssociationId=assoc_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"rule association {assoc_id} not removed within {timeout_s}s: {last!r}")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
