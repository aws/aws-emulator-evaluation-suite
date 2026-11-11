"""deploy-vpc-link-cfn-behaves."""
from __future__ import annotations

import time
import uuid
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-vpc-link-cfn-behaves"
GROUP = "state-machine"
SERVICES = ["apigatewayv2"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  VpcLinkName:
    Type: String
  SubnetIdList:
    Type: List<AWS::EC2::Subnet::Id>
Resources:
  MyVpcLink:
    Type: AWS::ApiGatewayV2::VpcLink
    Properties:
      Name: !Ref VpcLinkName
      SubnetIds: !Ref SubnetIdList
Outputs:
  VpcLinkId:
    Value: !Ref MyVpcLink
"""


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed VpcLink reaches AVAILABLE (per GetVpcLink) and can
    actually be wired into a real private HTTP_PROXY integration pointing at a real
    Network Load Balancer listener -- not merely report CREATE_COMPLETE."""
    subnet_ids = _pick_two_az_subnets(ctx)

    stack = _deploy_cfn_stack(
        ctx,
        _TEMPLATE,
        parameters={
            "VpcLinkName": ctx.unique_name("sim2real-apigwv2-vpclink-"),
            "SubnetIdList": ",".join(subnet_ids),
        },
    )
    vpc_link_id = stack["outputs"]["VpcLinkId"]

    apigwv2 = ctx.client("apigatewayv2")

    def _probe():
        return apigwv2.get_vpc_link(VpcLinkId=vpc_link_id)

    _poll_until(_probe, lambda r: r["VpcLinkStatus"] == "AVAILABLE", timeout_s=120.0, interval_s=5.0)
    confirm = apigwv2.get_vpc_link(VpcLinkId=vpc_link_id)
    assert confirm["VpcLinkStatus"] == "AVAILABLE", (
        f"expected the CFN-deployed VpcLink {vpc_link_id} to still read AVAILABLE on a "
        f"fresh independent GetVpcLink call, got {confirm['VpcLinkStatus']!r}"
    )

    # Now prove it is usable: build a real private integration on top of it.
    listener_arn, vpc_id = _create_nlb_listener(ctx, subnet_ids)

    api = apigwv2.create_api(
        Name=ctx.unique_name("sim2real-apigwv2-api-"), ProtocolType="HTTP"
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: apigwv2.delete_api(ApiId=api_id))

    integration = apigwv2.create_integration(
        ApiId=api_id,
        IntegrationType="HTTP_PROXY",
        IntegrationMethod="ANY",
        PayloadFormatVersion="1.0",
        ConnectionType="VPC_LINK",
        ConnectionId=vpc_link_id,
        IntegrationUri=listener_arn,
    )
    integration_id = integration["IntegrationId"]
    ctx.on_cleanup(
        lambda: apigwv2.delete_integration(ApiId=api_id, IntegrationId=integration_id)
    )

    fetched = apigwv2.get_integration(ApiId=api_id, IntegrationId=integration_id)
    assert fetched["ConnectionType"] == "VPC_LINK", (
        f"expected ConnectionType 'VPC_LINK' on the fetched integration, got "
        f"{fetched.get('ConnectionType')!r}"
    )
    assert fetched["ConnectionId"] == vpc_link_id, (
        f"expected ConnectionId {vpc_link_id!r} (the CFN-deployed VpcLink) on the fetched "
        f"integration, got {fetched.get('ConnectionId')!r}"
    )
    assert fetched["IntegrationUri"] == listener_arn, (
        f"expected IntegrationUri {listener_arn!r} (the real NLB listener) on the fetched "
        f"integration, got {fetched.get('IntegrationUri')!r}"
    )


def _pick_two_az_subnets(ctx) -> list[str]:
    """Create-or-adopt: use the shared network's subnets if it has 2+ AZs, else
    provision a dedicated VPC. A freshly provisioned account may have no
    shared network at all."""
    ec2 = ctx.client("ec2")
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        vpc_id = default_vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ])["Subnets"]
        by_az: dict[str, str] = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            return list(by_az.values())[:2]

    tags = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-apigwv2"}]
    vpc_id = ec2.create_vpc(
        CidrBlock="10.211.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": tags}]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ]
    if len(azs) < 2:
        raise AssertionError(
            f"region {ctx.region} does not have at least 2 available "
            "availability zones, required for the NLB"
        )
    subnet_ids = []
    for i in range(2):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.211.{i}.0/24",
            AvailabilityZone=azs[i]["ZoneName"],
            TagSpecifications=[{"ResourceType": "subnet", "Tags": tags}],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
    return subnet_ids


def _create_nlb_listener(ctx, subnet_ids: list[str]) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    suffix = uuid.uuid4().hex[:8]
    vpc_id = ec2.describe_subnets(SubnetIds=[subnet_ids[0]])["Subnets"][0]["VpcId"]

    elb_tags = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-apigwv2"}]

    tg = elbv2.create_target_group(
        Name=f"sim2real-tg-{suffix}",
        Protocol="TCP",
        Port=80,
        VpcId=vpc_id,
        TargetType="ip",
        Tags=elb_tags,
    )["TargetGroups"][0]
    tg_arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn))

    nlb = elbv2.create_load_balancer(
        Name=f"sim2real-nlb-{suffix}",
        Subnets=subnet_ids,
        Scheme="internal",
        Type="network",
        Tags=elb_tags,
    )["LoadBalancers"][0]
    nlb_arn = nlb["LoadBalancerArn"]

    def _delete_nlb() -> None:
        elbv2.delete_load_balancer(LoadBalancerArn=nlb_arn)
        elbv2.get_waiter("load_balancers_deleted").wait(LoadBalancerArns=[nlb_arn], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    ctx.on_cleanup(_delete_nlb)
    elbv2.get_waiter("load_balancer_available").wait(LoadBalancerArns=[nlb_arn], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    listener = elbv2.create_listener(
        LoadBalancerArn=nlb_arn,
        Protocol="TCP",
        Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Listeners"][0]
    listener_arn = listener["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))

    return listener_arn, vpc_id


def _deploy_cfn_stack(
    ctx, template_body: str, parameters: dict[str, str] | None = None, timeout_s: float = 900.0
) -> dict[str, Any]:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-apigwv2-stack-")
    params = [{"ParameterKey": k, "ParameterValue": v} for k, v in (parameters or {}).items()]

    def _cleanup() -> None:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=params,
        OnFailure="DELETE",
    )
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name,
        WaiterConfig={"Delay": 2, "MaxAttempts": max(1, int(timeout_s // 2))},
    )
    resp = cfn.describe_stacks(StackName=stack_name)
    outputs = {o["OutputKey"]: o["OutputValue"] for o in resp["Stacks"][0].get("Outputs", [])}
    return {"stack_name": stack_name, "outputs": outputs}


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation, and swallowing that leaks the VPC.
# So wait (bounded) for the ENIs to go, retry DependencyViolation inside the same window, and raise
# a final failure naming the ENIs still attached. The window is shared by all of one check's
# network deletes and fits a 900s cleanup budget.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]



def _delete_target_group_when_free(elbv2, arn, timeout_s=600.0, interval_s=10.0):
    """Delete a target group once no listener or deleting load balancer still uses it (ResourceInUse)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.delete_target_group(TargetGroupArn=arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "TargetGroupNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
