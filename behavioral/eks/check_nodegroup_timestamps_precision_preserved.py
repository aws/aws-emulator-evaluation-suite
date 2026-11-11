"""nodegroup-timestamps-precision-preserved."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "nodegroup-timestamps-precision-preserved"
GROUP = "representation"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A nodegroup's createdAt/modifiedAt read back identically across repeated DescribeNodegroup
    calls, both after creation and after an UpdateNodegroupConfig completes, with createdAt pinned
    to its original value while modifiedAt advances and then stabilizes."""
    eks = ctx.client("eks")
    cluster = _create_active_cluster(ctx)
    node_role_arn = _create_node_role(ctx)

    nodegroup_name = ctx.unique_name("sim2real-ng-")
    eks.create_nodegroup(
        clusterName=cluster["name"],
        nodegroupName=nodegroup_name,
        subnets=cluster["subnets"],
        nodeRole=node_role_arn,
        scalingConfig={"minSize": 1, "maxSize": 1, "desiredSize": 1},
        tags={"sim2real": "1"},
    )
    ctx.on_cleanup(lambda: _delete_nodegroup(ctx, cluster["name"], nodegroup_name))

    ng_1 = _poll_until(
        lambda: eks.describe_nodegroup(clusterName=cluster["name"], nodegroupName=nodegroup_name)["nodegroup"],
        lambda ng: ng["status"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=1500.0,
        interval_s=20.0,
    )
    assert ng_1["status"] == "ACTIVE", f"nodegroup ended as {ng_1['status']}: {ng_1.get('health')}"
    created_at_1 = ng_1["createdAt"]
    modified_at_1 = ng_1["modifiedAt"]

    # Immediate repeated read must return byte-identical timestamps.
    ng_2 = eks.describe_nodegroup(clusterName=cluster["name"], nodegroupName=nodegroup_name)["nodegroup"]
    assert ng_2["createdAt"] == created_at_1
    assert ng_2["modifiedAt"] == modified_at_1

    update_resp = eks.update_nodegroup_config(
        clusterName=cluster["name"],
        nodegroupName=nodegroup_name,
        labels={"addOrUpdateLabels": {"sim2real-marker": "true"}},
    )
    update_id = update_resp["update"]["id"]
    update = _poll_until(
        lambda: eks.describe_update(name=cluster["name"], nodegroupName=nodegroup_name, updateId=update_id)["update"],
        lambda u: u["status"] in ("Successful", "Failed", "Cancelled"),
        timeout_s=600.0,
        interval_s=15.0,
    )
    assert update["status"] == "Successful", f"nodegroup config update ended as {update['status']}: {update.get('errors')}"

    ng_3 = _poll_until(
        lambda: eks.describe_nodegroup(clusterName=cluster["name"], nodegroupName=nodegroup_name)["nodegroup"],
        lambda ng: ng["status"] == "ACTIVE",
        timeout_s=300.0,
        interval_s=10.0,
    )
    # createdAt must never move, even after an update; modifiedAt must have advanced.
    assert ng_3["createdAt"] == created_at_1
    modified_at_2 = ng_3["modifiedAt"]
    assert modified_at_2 >= modified_at_1

    # Repeated reads after the update must be stable/precision-preserving too.
    ng_4 = eks.describe_nodegroup(clusterName=cluster["name"], nodegroupName=nodegroup_name)["nodegroup"]
    assert ng_4["createdAt"] == created_at_1
    assert ng_4["modifiedAt"] == modified_at_2


# ===== helpers =====


def _retry_delete(fn):
    """Run one teardown delete; an already-gone resource is fine, every other error raises
    (_delete_net retries DependencyViolation itself)."""
    try:
        fn()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if not (code.endswith(".NotFound") or code == "ResourceNotFoundException"):
            raise


def _get_two_subnets(ctx):
    """Prefer the run's shared network (avoids the 5-VPC-per-region default quota being
    exhausted by repeated check runs); only create a dedicated VPC as a fallback -- a freshly
    provisioned account is not guaranteed to have the shared network. The fallback needs a real route
    to the internet (IGW + default route + public IPs), not just a VPC: nodegroup worker nodes
    must reach the EKS API endpoint and pull images to become ACTIVE."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        by_az: dict[str, str] = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            return list(by_az.values())[:2]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.43.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-vpc-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[
            {"ResourceType": "internet-gateway", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-igw-")}]}
        ]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    def _teardown_igw():
        _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id)
        _retry_delete(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))

    ctx.on_cleanup(_teardown_igw)

    rt_id = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "route-table", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-rt-")}]}
        ],
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rt_id)))
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    azs = [a["ZoneName"] for a in ec2.describe_availability_zones()["AvailabilityZones"]][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.43.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-eks-subnet-{i}-")}]}
            ],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=sid: _retry_delete(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        ec2.modify_subnet_attribute(SubnetId=sid, MapPublicIpOnLaunch={"Value": True})
        assoc_id = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=sid)["AssociationId"]
        ctx.on_cleanup(lambda aid=assoc_id: _retry_delete(lambda: ec2.disassociate_route_table(AssociationId=aid)))
        subnet_ids.append(sid)
    if len(subnet_ids) < 2:
        raise AssertionError(f"could not provision subnets in two availability zones (got {subnet_ids!r})")
    return subnet_ids


def _create_cluster_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-managed", "Value": "true"}],
    )
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_node_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-noderole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-managed", "Value": "true"}],
    )
    managed_policies = [
        "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
        "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
        "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    ]
    for policy_arn in managed_policies:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        for policy_arn in managed_policies:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _poll_until(probe, predicate, timeout_s=1200.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _wait_cluster_status(ctx, name, statuses, timeout_s=1200.0, interval_s=15.0):
    eks = ctx.client("eks")
    return _poll_until(
        lambda: eks.describe_cluster(name=name)["cluster"],
        lambda c: c["status"] in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
    )


def _create_active_cluster(ctx):
    eks = ctx.client("eks")
    name = ctx.unique_name("sim2real-eks-")
    subnets = _get_two_subnets(ctx)
    role_arn = _create_cluster_role(ctx)
    eks.create_cluster(
        name=name,
        roleArn=role_arn,
        resourcesVpcConfig={"subnetIds": subnets},
        tags={"sim2real": "1"},
    )

    def _cleanup():
        try:
            _wait_cluster_status(ctx, name, {"ACTIVE", "FAILED"}, timeout_s=1200.0)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        try:
            eks.delete_cluster(name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        deadline = time.monotonic() + 900.0
        while time.monotonic() < deadline:
            try:
                eks.describe_cluster(name=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
                break
            time.sleep(15.0)

    ctx.on_cleanup(_cleanup)
    desc = _wait_cluster_status(ctx, name, {"ACTIVE", "FAILED"}, timeout_s=1200.0)
    if desc["status"] != "ACTIVE":
        raise AssertionError(f"cluster {name} entered status {desc['status']} instead of ACTIVE")
    return {"name": name, "arn": desc["arn"], "role_arn": role_arn, "subnets": subnets}


def _delete_nodegroup(ctx, cluster_name, nodegroup_name):
    eks = ctx.client("eks")
    try:
        _poll_until(
            lambda: eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)["nodegroup"],
            lambda ng: ng["status"] in ("ACTIVE", "CREATE_FAILED", "DEGRADED"),
            timeout_s=1500.0,
            interval_s=20.0,
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        eks.delete_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + 900.0
    while time.monotonic() < deadline:
        try:
            eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        time.sleep(2)
    raise AssertionError(f"nodegroup {nodegroup_name} was not deleted within 900 s")


# A cluster or other resource in this VPC deletes asynchronously and leaves its ENIs behind for a while,
# so an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Teardown
# waits (bounded) for the ENIs, retries DependencyViolation in one window shared by the check's network
# deletes, then raises naming any ENIs still attached. Teardown-only: run() never calls this.
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
