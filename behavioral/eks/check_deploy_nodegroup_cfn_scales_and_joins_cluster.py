"""deploy-nodegroup-cfn-scales-and-joins-cluster."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-nodegroup-cfn-scales-and-joins-cluster"
GROUP = "deploy"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed AWS::EKS::Nodegroup reaches ACTIVE with exactly the template's
    scaling configuration and is listed by ListNodegroups on its cluster, so the CFN
    resource drove a real nodegroup rather than only a stack record."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    eks = ctx.client("eks")
    cfn = ctx.client("cloudformation")

    vpc_id, subnet_ids = _create_vpc_and_subnets(ctx, ec2)
    cluster_role_arn = _create_cluster_role(ctx, iam)
    node_role_arn = _create_node_role(ctx, iam)

    cluster_name = ctx.unique_name("sim2real-eks-cl-")
    _call_with_role_propagation_retry(
        lambda: eks.create_cluster(
            name=cluster_name,
            roleArn=cluster_role_arn,
            resourcesVpcConfig={"subnetIds": subnet_ids},
        )
    )
    ctx.on_cleanup(lambda: _delete_cluster(eks, cluster_name))
    _poll_until(
        lambda: eks.describe_cluster(name=cluster_name)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "FAILED"),
        timeout_s=1200,
        interval_s=20,
    )
    final_status = eks.describe_cluster(name=cluster_name)["cluster"]["status"]
    assert final_status == "ACTIVE", f"expected cluster ACTIVE, got {final_status}"

    stack_name = ctx.unique_name("sim2real-eks-ngstack-")
    nodegroup_name = ctx.unique_name("sim2real-eks-ng-")
    scaling = {"MinSize": 1, "MaxSize": 3, "DesiredSize": 2}

    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {
                "ClusterNameParam": {"Type": "String"},
                "NodegroupNameParam": {"Type": "String"},
                "NodeRoleArnParam": {"Type": "String"},
                "SubnetIdsParam": {"Type": "List<AWS::EC2::Subnet::Id>"},
            },
            "Resources": {
                "Nodegroup": {
                    "Type": "AWS::EKS::Nodegroup",
                    "Properties": {
                        "ClusterName": {"Ref": "ClusterNameParam"},
                        "NodegroupName": {"Ref": "NodegroupNameParam"},
                        "NodeRole": {"Ref": "NodeRoleArnParam"},
                        "Subnets": {"Ref": "SubnetIdsParam"},
                        "ScalingConfig": scaling,
                        "InstanceTypes": ["t3.medium"],
                        "AmiType": "AL2023_x86_64_STANDARD",
                    },
                }
            },
            "Outputs": {
                "NodegroupNameOut": {"Value": {"Fn::GetAtt": ["Nodegroup", "NodegroupName"]}}
            },
        }
    )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Parameters=[
            {"ParameterKey": "ClusterNameParam", "ParameterValue": cluster_name},
            {"ParameterKey": "NodegroupNameParam", "ParameterValue": nodegroup_name},
            {"ParameterKey": "NodeRoleArnParam", "ParameterValue": node_role_arn},
            {"ParameterKey": "SubnetIdsParam", "ParameterValue": ",".join(subnet_ids)},
        ],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1500}
    )

    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    assert outputs["NodegroupNameOut"] == nodegroup_name, (
        f"expected stack Output NodegroupNameOut == {nodegroup_name!r}, got {outputs.get('NodegroupNameOut')!r}"
    )

    described = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)[
        "nodegroup"
    ]
    assert described["status"] == "ACTIVE", f"unexpected status: {described['status']}"
    assert described["scalingConfig"] == {"minSize": 1, "maxSize": 3, "desiredSize": 2}, described[
        "scalingConfig"
    ]

    listed = eks.list_nodegroups(clusterName=cluster_name)["nodegroups"]
    assert nodegroup_name in listed, f"expected {nodegroup_name!r} in ListNodegroups, got {listed}"


# ===== helpers =====


def _call_with_role_propagation_retry(fn, *, timeout_s: float = 60.0, interval_s: float = 5.0) -> Any:
    """A just-created IAM role can take a few seconds to become assumable; retry the
    call that depends on it instead of sleeping blind before making it."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            last_err = err
            time.sleep(interval_s)
    assert last_err is not None
    raise last_err


def _poll_until(probe, predicate, timeout_s: float, interval_s: float = 15.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


# Not-found codes of the teardown calls below: the resource is already gone.
_GONE_CODES = {
    "NoSuchEntity",
    "InvalidVpcID.NotFound",
    "InvalidInternetGatewayID.NotFound",
    "InvalidRouteTableID.NotFound",
    "InvalidSubnetID.NotFound",
    "InvalidAssociationID.NotFound",
    "Gateway.NotAttached",
}


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in _GONE_CODES:
            raise


def _tag_spec(resource_type: str, name: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
    }


def _delete_stack(cfn, stack_name: str) -> None:
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450}
    )


def _delete_cluster(eks, cluster_name: str) -> None:
    try:
        eks.delete_cluster(name=cluster_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=cluster_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        time.sleep(2)
    raise AssertionError(f"cluster {cluster_name} still exists 900s after DeleteCluster")


def _delete_role(iam, role_name: str, policy_arns: list[str]) -> None:
    for arn in policy_arns:
        _safe(lambda a=arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=a))
    _safe(lambda: iam.delete_role(RoleName=role_name))


def _create_cluster_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-eks-clrole-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _delete_role(iam, role_name, [policy_arn]))
    _poll_until(
        lambda: iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"],
        lambda pols: any(p["PolicyArn"] == policy_arn for p in pols),
        timeout_s=30,
        interval_s=3,
    )
    return role_arn


def _create_node_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-eks-noderole-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    policy_arns = [
        "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
        "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
        "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    ]
    for arn in policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
    ctx.on_cleanup(lambda: _delete_role(iam, role_name, policy_arns))
    _poll_until(
        lambda: {p["PolicyArn"] for p in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]},
        lambda attached: set(policy_arns).issubset(attached),
        timeout_s=30,
        interval_s=3,
    )
    return role_arn


def _create_vpc_and_subnets(ctx, ec2) -> tuple[str, list[str]]:
    vpc_id = ec2.create_vpc(
        CidrBlock="10.78.0.0/16",
        TagSpecifications=[_tag_spec("vpc", ctx.unique_name("sim2real-eks-vpc-"))],
    )["Vpc"]["VpcId"]
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ]
    az_names = [az["ZoneName"] for az in azs[:2]]
    if len(az_names) < 2:
        raise AssertionError("region does not have at least 2 available AZs for EKS subnets")

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[_tag_spec("internet-gateway", ctx.unique_name("sim2real-eks-igw-"))]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    rt_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=[_tag_spec("route-table", ctx.unique_name("sim2real-eks-rt-"))]
    )["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    subnet_ids: list[str] = []
    assoc_ids: list[str] = []
    for i, az in enumerate(az_names):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.78.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec("subnet", ctx.unique_name(f"sim2real-eks-subnet{i}-"))],
        )["Subnet"]["SubnetId"]
        ec2.modify_subnet_attribute(SubnetId=sid, MapPublicIpOnLaunch={"Value": True})
        aid = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=sid)["AssociationId"]
        subnet_ids.append(sid)
        assoc_ids.append(aid)

    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id)))
    ctx.on_cleanup(
        lambda: _safe(lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id))
    )
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rt_id)))
    for sid, aid in zip(subnet_ids, assoc_ids):
        ctx.on_cleanup(lambda sid=sid: _safe(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        ctx.on_cleanup(lambda aid=aid: _safe(lambda: ec2.disassociate_route_table(AssociationId=aid)))

    return vpc_id, subnet_ids


# AWS-managed ENIs (endpoints, load balancers, functions) leave a VPC asynchronously after their
# owner's delete returns, so DeleteSubnet/DeleteSecurityGroup/DeleteVpc can fail with
# DependencyViolation. Wait (bounded) for the ENIs to go, retry inside the same window, and raise
# naming any ENIs still attached. Teardown-only: run() never calls this.
_NET_TEARDOWN_S = 540.0
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
        _time.sleep(2)
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
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
