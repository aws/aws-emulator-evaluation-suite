"""deploy-cluster-cfn-becomes-active-and-usable."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "deploy-cluster-cfn-becomes-active-and-usable"
GROUP = "deploy"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed AWS::EKS::Cluster is ACTIVE and functionally live, not merely stack-complete:
    a node group created on it reaches ACTIVE and appears in ListNodegroups."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    eks = ctx.client("eks")
    cfn = ctx.client("cloudformation")

    vpc_id, subnet_ids = _create_vpc_and_subnets(ctx, ec2)
    cluster_role_arn = _create_cluster_role(ctx, iam)
    node_role_arn = _create_node_role(ctx, iam)

    cluster_name = ctx.unique_name("sim2real-eks-cl-")
    stack_name = ctx.unique_name("sim2real-eks-stack-")

    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {
                "ClusterName": {"Type": "String"},
                "ClusterRoleArn": {"Type": "String"},
                "SubnetIdsParam": {"Type": "List<AWS::EC2::Subnet::Id>"},
            },
            "Resources": {
                "Cluster": {
                    "Type": "AWS::EKS::Cluster",
                    "Properties": {
                        "Name": {"Ref": "ClusterName"},
                        "RoleArn": {"Ref": "ClusterRoleArn"},
                        "ResourcesVpcConfig": {"SubnetIds": {"Ref": "SubnetIdsParam"}},
                    },
                }
            },
            "Outputs": {"ClusterNameOut": {"Value": {"Ref": "Cluster"}}},
        }
    )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Parameters=[
            {"ParameterKey": "ClusterName", "ParameterValue": cluster_name},
            {"ParameterKey": "ClusterRoleArn", "ParameterValue": cluster_role_arn},
            {"ParameterKey": "SubnetIdsParam", "ParameterValue": ",".join(subnet_ids)},
        ],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))

    try:
        cfn.get_waiter("stack_create_complete").wait(
            StackName=stack_name,
            WaiterConfig={"Delay": 2, "MaxAttempts": max(1, int(_budget_s(ctx, 3000) / 2))},
        )
    except WaiterError:
        if _budget_spent(ctx):
            raise TimeoutError(f"stack {stack_name} CREATE_COMPLETE: the run budget ended first; not graded") from None
        raise

    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    assert outputs["ClusterNameOut"] == cluster_name

    described = eks.describe_cluster(name=cluster_name)["cluster"]
    assert described["status"] == "ACTIVE"

    # Reaching ACTIVE means real worker nodes joined the control plane.
    nodegroup_name = ctx.unique_name("sim2real-eks-ng-")
    _create_nodegroup_with_retry(
        eks,
        ctx=ctx,
        timeout_s=_budget_s(ctx, 180),
        clusterName=cluster_name,
        nodegroupName=nodegroup_name,
        subnets=subnet_ids,
        nodeRole=node_role_arn,
        scalingConfig={"minSize": 1, "maxSize": 1, "desiredSize": 1},
        instanceTypes=["t3.medium"],
        amiType="AL2023_x86_64_STANDARD",
    )
    ctx.on_cleanup(lambda: _delete_nodegroup(eks, cluster_name, nodegroup_name))

    final = _poll_until(
        lambda: eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)[
            "nodegroup"
        ],
        lambda ng: ng["status"] in ("ACTIVE", "CREATE_FAILED"),
        ctx=ctx,
        timeout_s=_budget_s(ctx, 1500),
        interval_s=2,
    )
    assert final["status"] == "ACTIVE", f"nodegroup did not reach ACTIVE: {final}"

    listed = eks.list_nodegroups(clusterName=cluster_name)["nodegroups"]
    assert nodegroup_name in listed


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _create_nodegroup_with_retry(eks, *, timeout_s: float = 180.0, interval_s: float = 2.0, ctx=None, **kwargs) -> None:
    """CreateNodegroup, retrying only the InvalidParameterException a fresh node role raises
    while IAM propagation is in flight."""
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            eks.create_nodegroup(**kwargs)
            return
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            if last_code == "InvalidParameterException":
                time.sleep(interval_s)
                continue
            raise
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("CreateNodegroup past IAM role propagation: the run budget ended first; not graded")
    raise AssertionError(
        f"CreateNodegroup kept failing with {last_code} after {timeout_s}s (IAM role propagation?)"
    )


def _poll_until(probe, predicate, timeout_s: float, interval_s: float = 15.0, ctx=None) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("the polled condition: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


_GONE = ("NoSuchEntity", "InvalidVpcID.NotFound", "InvalidInternetGatewayID.NotFound",
         "Gateway.NotAttached", "InvalidRouteTableID.NotFound", "InvalidSubnetID.NotFound",
         "InvalidAssociationID.NotFound")


def _safe(fn) -> None:
    """One teardown step; only the resource already being gone is tolerated."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in _GONE:
            raise


def _tag_spec(resource_type: str, name: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
    }


def _delete_stack(cfn, stack_name: str) -> None:
    _safe(lambda: cfn.delete_stack(StackName=stack_name))
    try:
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 840}
        )
    except WaiterError as last:
        raise RuntimeError(f"stack {stack_name} was not deleted: {last!r}") from last


def _delete_nodegroup(eks, cluster_name: str, nodegroup_name: str) -> None:
    try:
        eks.delete_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    deadline = time.monotonic() + 1200
    last = None
    while time.monotonic() < deadline:
        try:
            last = eks.describe_nodegroup(
                clusterName=cluster_name, nodegroupName=nodegroup_name)["nodegroup"].get("status")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        time.sleep(3)
    raise RuntimeError(f"nodegroup {nodegroup_name} was not deleted: {last!r}")


def _delete_role(iam, role_name: str, policy_arns: list[str]) -> None:
    failures = []
    for step in [lambda a=arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=a)
                 for arn in policy_arns] + [lambda: iam.delete_role(RoleName=role_name)]:
        try:
            _safe(step)
        except ClientError as exc:
            failures.append(exc)
    if failures:
        raise RuntimeError(f"role {role_name} was not deleted: {failures!r}")


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
        CidrBlock="10.77.0.0/16",
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
            CidrBlock=f"10.77.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec("subnet", ctx.unique_name(f"sim2real-eks-subnet{i}-"))],
        )["Subnet"]["SubnetId"]
        ec2.modify_subnet_attribute(SubnetId=sid, MapPublicIpOnLaunch={"Value": True})
        aid = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=sid)["AssociationId"]
        subnet_ids.append(sid)
        assoc_ids.append(aid)

    # Cleanups run LIFO, so register them in reverse of the teardown order.
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


# EC2 network teardown waits for AWS-managed ENIs to leave before deleting: dependents in the VPC
# delete asynchronously, so an immediate DeleteSubnet/DeleteVpc fails with DependencyViolation.
# The bounded window is shared by all of one check's network deletes and fits the cleanup budget.
_NET_TEARDOWN_S = 1260.0
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
        _time.sleep(3)
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
        _time.sleep(3)


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
