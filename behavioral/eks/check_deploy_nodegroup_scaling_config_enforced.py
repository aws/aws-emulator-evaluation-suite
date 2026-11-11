"""deploy-nodegroup-scaling-config-enforced."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "deploy-nodegroup-scaling-config-enforced"
GROUP = "deploy"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed nodegroup enforces its scaling bounds: UpdateNodegroupConfig with desiredSize
    above maxSize is InvalidParameterException and leaves the config unchanged, while an in-bounds
    update takes effect."""
    net = _create_vpc_with_subnets(ctx)
    cluster_role_arn = _create_cluster_role(ctx)
    node_role_arn = _create_node_role(ctx)

    eks = ctx.client("eks")
    cluster_name = ctx.unique_name("sim2real-ekscl-")
    _create_cluster(ctx, eks, cluster_name, cluster_role_arn, net["subnet_ids"])

    nodegroup_name = ctx.unique_name("sim2real-eksng-")
    template = json.dumps(
        {
            "Resources": {
                "Nodegroup": {
                    "Type": "AWS::EKS::Nodegroup",
                    "Properties": {
                        "ClusterName": cluster_name,
                        "NodegroupName": nodegroup_name,
                        "NodeRole": node_role_arn,
                        "Subnets": net["subnet_ids"],
                        "InstanceTypes": ["t3.small"],
                        "ScalingConfig": {"MinSize": 1, "MaxSize": 2, "DesiredSize": 1},
                    },
                }
            }
        }
    )
    _deploy_cfn_stack(ctx, template, timeout_s=1500)

    nodegroup = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)["nodegroup"]
    assert nodegroup["status"] == "ACTIVE", f"expected ACTIVE, got {nodegroup['status']!r}"
    scaling = nodegroup["scalingConfig"]
    actual_scaling = (scaling["minSize"], scaling["maxSize"], scaling["desiredSize"])
    assert actual_scaling == (1, 2, 1), f"expected (min,max,desired)=(1, 2, 1), got {actual_scaling!r}"

    code, message = _error(
        lambda: eks.update_nodegroup_config(
            clusterName=cluster_name,
            nodegroupName=nodegroup_name,
            scalingConfig={"desiredSize": 5},
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    assert message == "desired capacity 5 can't be greater than max size 2", f"unexpected message {message!r}"

    unchanged = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)["nodegroup"][
        "scalingConfig"
    ]
    actual_unchanged = (unchanged["minSize"], unchanged["maxSize"], unchanged["desiredSize"])
    assert actual_unchanged == (1, 2, 1), (
        f"expected rejected update to leave (min,max,desired)=(1, 2, 1), got {actual_unchanged!r}"
    )

    eks.update_nodegroup_config(
        clusterName=cluster_name,
        nodegroupName=nodegroup_name,
        scalingConfig={"desiredSize": 2},
    )
    updated = _poll_until(
        lambda: eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)["nodegroup"],
        lambda ng: ng["status"] == "ACTIVE" and ng["scalingConfig"]["desiredSize"] == 2,
        timeout_s=600.0,
        interval_s=15.0,
    )
    assert updated["scalingConfig"]["desiredSize"] == 2, (
        f"expected in-bounds update to take effect with desiredSize=2, got {updated['scalingConfig']!r}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last value={value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


def _error(fn):
    """Call fn, require it raises ClientError, return the error (Code, Message)."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _tagspec_ec2(resource_type, name):
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _create_vpc_with_subnets(ctx):
    ec2 = ctx.client("ec2")
    tag = ctx.unique_name("sim2real-eksvpc")
    vpc_id = ec2.create_vpc(CidrBlock="10.43.0.0/16", TagSpecifications=[_tagspec_ec2("vpc", tag)])["Vpc"]["VpcId"]
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    azs = [
        a["ZoneName"]
        for a in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ]
    ][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.43.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tagspec_ec2("subnet", f"{tag}-{i}")],
        )["Subnet"]["SubnetId"]
        ec2.modify_subnet_attribute(SubnetId=sid, MapPublicIpOnLaunch={"Value": True})
        subnet_ids.append(sid)
    igw_id = ec2.create_internet_gateway(TagSpecifications=[_tagspec_ec2("internet-gateway", tag)])[
        "InternetGateway"
    ]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    rt_id = ec2.create_route_table(VpcId=vpc_id, TagSpecifications=[_tagspec_ec2("route-table", tag)])[
        "RouteTable"
    ]["RouteTableId"]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    for sid in subnet_ids:
        ec2.associate_route_table(RouteTableId=rt_id, SubnetId=sid)

    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))
    ctx.on_cleanup(lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id))
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rt_id))
    for sid in subnet_ids:
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids}


def _create_cluster_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-eks-cluster-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn))
    return role_arn


def _create_node_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-eks-node-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    policies = [
        "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
        "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
        "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    ]
    for p in policies:
        iam.attach_role_policy(RoleName=name, PolicyArn=p)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    for p in policies:
        ctx.on_cleanup(lambda p=p: iam.detach_role_policy(RoleName=name, PolicyArn=p))
    return role_arn


def _create_cluster(ctx, eks, name, role_arn, subnet_ids, timeout_s=1200.0):
    deadline = time.monotonic() + 90.0
    while True:
        try:
            eks.create_cluster(name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids})
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterException" and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise
    ctx.on_cleanup(lambda: eks.delete_cluster(name=name))
    status = _poll_until(
        lambda: eks.describe_cluster(name=name)["cluster"]["status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=timeout_s,
        interval_s=20.0,
    )
    if status != "ACTIVE":
        raise AssertionError(f"cluster {name} ended in status {status}")
    return name


def _stack_status(cfn, stack_name):
    try:
        return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    except ClientError:
        return None


def _deploy_cfn_stack(ctx, template_body, timeout_s=1500.0):
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-eks-stack-")

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        _poll_until(
            lambda: _stack_status(cfn, stack_name),
            lambda s: s is None or s == "DELETE_COMPLETE",
            timeout_s=timeout_s,
            interval_s=15.0,
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    ctx.on_cleanup(_cleanup)
    status = _poll_until(
        lambda: _stack_status(cfn, stack_name),
        lambda s: s in ("CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"),
        timeout_s=timeout_s,
        interval_s=15.0,
    )
    if status != "CREATE_COMPLETE":
        raise AssertionError(f"stack {stack_name} ended in {status}, expected CREATE_COMPLETE")
    return stack_name


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
