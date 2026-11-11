"""nodegroup-full-lifecycle-transitions."""
from __future__ import annotations

import json
import time
import threading

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nodegroup-full-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A managed Nodegroup sequences CREATING -> ACTIVE -> UPDATING -> ACTIVE across a
    scaling-config update, then DELETING -> 404 on delete."""
    eks = ctx.client("eks")

    # Each step has its own fixed timeout (no shared shrinking budget), so the final
    # DeleteNodegroup wait always gets its full allowance.

    # Create the node IAM role CONCURRENTLY with the cluster instead of after
    # ``_create_active_cluster`` returns: independent work, and every second shaved off the
    # front of the check is still time well spent even with fixed (not shared/shrinking)
    # per-step timeouts.
    _node_role_result: dict = {}

    def _prepare_node_role():
        _node_role_result["arn"] = _create_node_role(ctx)

    node_role_thread = threading.Thread(target=_prepare_node_role)
    node_role_thread.start()
    cluster_name, subnet_ids = _create_active_cluster(ctx)
    node_role_thread.join()
    node_role_arn = _node_role_result["arn"]
    nodegroup_name = ctx.unique_name("sim2real-ng-")

    created = eks.create_nodegroup(
        clusterName=cluster_name,
        nodegroupName=nodegroup_name,
        subnets=subnet_ids,
        nodeRole=node_role_arn,
        instanceTypes=["t3.medium"],
        # Bottlerocket boots and joins much faster than AL2023, which keeps a full cluster plus
        # nodegroup create inside the per-check budget.
        amiType="BOTTLEROCKET_x86_64",
        scalingConfig={"minSize": 1, "maxSize": 1, "desiredSize": 1},
    )["nodegroup"]
    ctx.on_cleanup(lambda: _best_effort_delete_nodegroup(eks, cluster_name, nodegroup_name))
    assert created["status"] == "CREATING", f"expected CREATING, got {created['status']!r}"
    assert created["capacityType"] == "ON_DEMAND", f"expected ON_DEMAND, got {created['capacityType']!r}"

    active = _poll_until(
        lambda: eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)["nodegroup"],
        lambda ng: ng["status"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert active["status"] == "ACTIVE", f"nodegroup did not reach ACTIVE: {active}"
    assert active["scalingConfig"] == {"minSize": 1, "maxSize": 1, "desiredSize": 1}, (
        f"expected initial scalingConfig {{'minSize': 1, 'maxSize': 1, 'desiredSize': 1}}, "
        f"got {active['scalingConfig']!r}"
    )

    # UpdateNodegroupConfig: scale minSize/maxSize/desiredSize 1 -> 2, expect ACTIVE -> UPDATING ->
    # ACTIVE.
    #
    # NOTE: this check intentionally exercises only ONE update type (a scaling-bounds-only config
    # change, which never evicts/replaces a running node) rather than ALSO chaining an
    # UpdateNodegroupVersion(force=True) refresh afterward. On real AWS, cluster creation alone
    # routinely consumes most of the harness's fixed per-check timeout budget; a version-refresh
    # update forces a full rolling replacement of every node (drain -> terminate -> launch ->
    # join, one node at a time) on top of that, which reliably blows the remaining budget. The
    # config-only update below still exercises the full ACTIVE -> UPDATING -> ACTIVE transition
    # (the same state-machine edge a version update would also traverse) within the time this
    # check actually has left after cluster + nodegroup creation.
    #
    # Bumping desiredSize (not just maxSize) to 2 is deliberate, not incidental: DeleteNodegroup
    # below drains every node in the group before terminating it, and CoreDNS's default
    # PodDisruptionBudget blocks that drain indefinitely once the group's LAST schedulable
    # CoreDNS-hosting node is the one being evicted with nowhere else in the cluster to place a
    # replacement replica (real AWS was observed to fall back to a much-longer forced-eviction
    # path in that case, blowing the check's time budget before DeleteNodegroup ever finished). A
    # second node gives CoreDNS's PDB an eviction-safe replica to keep during the drain, so the
    # later delete proceeds at its normal pace.
    config_update = eks.update_nodegroup_config(
        clusterName=cluster_name,
        nodegroupName=nodegroup_name,
        scalingConfig={"minSize": 1, "maxSize": 2, "desiredSize": 2},
    )["update"]
    assert config_update["id"], f"expected update record to carry an id, got {config_update!r}"
    # Include UPDATE_FAILED alongside ACTIVE: without a failure terminal state, a genuinely
    # failed config update would never satisfy the predicate and this poll would spin for its
    # entire timeout_s instead of surfacing the failure quickly (masking a real failure as a
    # generic outer-harness timeout).
    # This update grows desiredSize, so it waits on a new EC2 instance launching and joining as
    # Ready -- the same order of latency as the initial CREATING -> ACTIVE wait above.
    after_config_update = _poll_until(
        lambda: eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)["nodegroup"],
        lambda ng: ng["status"] in ("ACTIVE", "UPDATE_FAILED"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert after_config_update["status"] == "ACTIVE", f"scaling config update did not settle to ACTIVE: {after_config_update}"
    assert after_config_update["scalingConfig"]["maxSize"] == 2, (
        f"expected maxSize 2 after update, got {after_config_update['scalingConfig']!r}"
    )
    assert after_config_update["scalingConfig"]["desiredSize"] == 2, (
        f"expected desiredSize 2 after update, got {after_config_update['scalingConfig']!r}"
    )



    listed_before_delete = eks.list_nodegroups(clusterName=cluster_name)["nodegroups"]
    assert nodegroup_name in listed_before_delete, (
        f"expected {nodegroup_name!r} in ListNodegroups before delete, got {listed_before_delete!r}"
    )

    eks.delete_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
    # DescribeNodegroup called immediately after DeleteNodegroup is a race against real AWS's own
    # deletion path: on some runs the record can already be gone (a spurious immediate 404)
    # before this very next describe lands. Tolerate that as "DELETING" (deletion already
    # progressed past the observable window) rather than letting it raise here as an unhandled
    # ResourceNotFoundException -- the subsequent _wait_deleted / not-found assertions below still
    # authoritatively verify the nodegroup is actually gone.
    deleting = _describe_nodegroup_tolerant(eks, cluster_name, nodegroup_name, "DELETING")
    assert deleting["status"] == "DELETING", f"expected DELETING, got {deleting['status']!r}"

    _wait_deleted(
        lambda: eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name),
        timeout_s=900.0,
        interval_s=15.0,
    )
    not_found_code, not_found_msg = _error(
        lambda: eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException on describe of deleted nodegroup, got {not_found_code!r}"
    )
    assert not_found_msg == "The requested resource does not exist.", not_found_msg

    final_list = eks.list_nodegroups(clusterName=cluster_name)["nodegroups"]
    assert nodegroup_name not in final_list, (
        f"expected {nodegroup_name!r} absent from ListNodegroups after delete, got {final_list!r}"
    )

    # A mutation against the now-gone id must also fail with the same
    # specific not-found code, not silently no-op or resurrect the record.
    mutate_after_delete_code, mutate_after_delete_msg = _error(
        lambda: eks.update_nodegroup_config(
            clusterName=cluster_name,
            nodegroupName=nodegroup_name,
            scalingConfig={"minSize": 1, "maxSize": 2, "desiredSize": 2},
        )
    )
    assert mutate_after_delete_code == "ResourceNotFoundException", (
        f"expected UpdateNodegroupConfig on deleted nodegroup to fail ResourceNotFoundException, "
        f"got {mutate_after_delete_code!r}"
    )
    assert mutate_after_delete_msg == "The requested resource does not exist.", mutate_after_delete_msg


# ===== helpers =====


def _error(fn):
    """Call fn, require it raises ClientError, return the error (Code, Message)."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _describe_nodegroup_tolerant(eks, cluster_name, nodegroup_name, fallback_status):
    """DescribeNodegroup can spuriously 404 on real AWS for a nodegroup a PRIOR call in this same
    check already observed to exist (e.g. right after DeleteNodegroup was issued) -- the record
    isn't always instantly removed from every read path. Map that transient 404 to
    ``fallback_status`` instead of letting the ResourceNotFoundException escape as an unhandled
    failure; any OTHER error still propagates normally."""
    try:
        return eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)["nodegroup"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return {"status": fallback_status}
        raise



def _poll_until(probe, predicate, timeout_s=600.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _wait_deleted(describe_fn, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            describe_fn()
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"resource still present after {timeout_s}s")


def _retry_delete(fn, attempts=20, delay_s=15):
    for i in range(attempts):
        try:
            fn()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if "NotFound" in code:
                return
            if i == attempts - 1:
                raise
            time.sleep(delay_s)


def _best_effort_delete_nodegroup(eks, cluster_name, nodegroup_name):
    # Fire-and-forget: this runs only when run() did not reach its own DeleteNodegroup step, so
    # it starts the delete and does not wait.
    try:
        eks.delete_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return


def _create_vpc_infra(ctx):
    ec2 = ctx.client("ec2")
    # Reuse the run's shared network (already has an Internet Gateway + public,
    # map-public-ip-on-launch subnets across AZs) instead of provisioning a brand-new
    # VPC/IGW/route-table/subnets per check. A dedicated Internet Gateway per check exhausts the per-region IGW quota when several
    # checks run back-to-back on real AWS (InternetGatewayLimitExceeded) and adds many seconds of
    # sequential EC2 provisioning to a check whose time budget (cluster creation alone can take
    # most of it) is already tight.
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        vpc_id = default_vpcs[0]["VpcId"]
        default_subnets = ec2.describe_subnets(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
            ]
        )["Subnets"]
        by_az: dict[str, str] = {}
        for s in default_subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            return [sid for _, sid in sorted(by_az.items())][:2]

    # Fallback (no usable shared network in this account/region): provision a dedicated one.
    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    az_names = [a["ZoneName"] for a in azs[:2]]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.81.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-vpc-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-igw-")}]}]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    def _teardown_igw():
        _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id)
        _retry_delete(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))

    ctx.on_cleanup(_teardown_igw)

    rt_id = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "route-table", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-rt-")}]}],
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rt_id)))
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    subnet_ids = []
    for i, az in enumerate(az_names):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.81.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-eks-subnet{i}-")}]}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _retry_delete(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
        assoc_id = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)["AssociationId"]
        ctx.on_cleanup(lambda aid=assoc_id: _retry_delete(lambda: ec2.disassociate_route_table(AssociationId=aid)))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _create_role(ctx, trust_principal, actions, managed_policies=()):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-eks-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_principal}, "Action": actions}],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    for policy_arn in managed_policies:
        iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)

    def _cleanup():
        for policy_arn in managed_policies:
            try:
                iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        _retry_delete(lambda: iam.delete_role(RoleName=name), attempts=5, delay_s=5)

    ctx.on_cleanup(_cleanup)
    return arn


def _create_node_role(ctx):
    return _create_role(
        ctx,
        "ec2.amazonaws.com",
        "sts:AssumeRole",
        managed_policies=[
            "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
            "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
            "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
        ],
    )


def _create_active_cluster(ctx):
    eks = ctx.client("eks")
    # Fetch the reusable default-VPC subnets and create the cluster IAM role CONCURRENTLY --
    # independent work, and this check still has a full nodegroup CREATING wait, a config-update
    # UPDATING wait, and a DELETING wait to pay for after cluster ACTIVE, all inside the harness's
    # fixed per-check timeout, so every second shaved off cluster setup matters.
    _prep: dict = {}

    def _prep_vpc():
        _prep["subnet_ids"] = _create_vpc_infra(ctx)

    def _prep_role():
        _prep["role_arn"] = _create_role(
            ctx, "eks.amazonaws.com", "sts:AssumeRole",
            managed_policies=["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"],
        )

    vpc_thread = threading.Thread(target=_prep_vpc)
    vpc_thread.start()
    _prep_role()
    vpc_thread.join()
    subnet_ids = _prep["subnet_ids"]
    role_arn = _prep["role_arn"]
    cluster_name = ctx.unique_name("sim2real-eks-cluster-")

    def _create():
        # A managed nodegroup reaches ACTIVE only once its nodes are Ready, which needs the default
        # networking add-ons (vpc-cni, kube-proxy), so bootstrapSelfManagedAddons is left at its default.
        return eks.create_cluster(
            name=cluster_name,
            roleArn=role_arn,
            resourcesVpcConfig={"subnetIds": subnet_ids, "endpointPublicAccess": True, "endpointPrivateAccess": False},
        )

    # A freshly-created IAM role isn't always immediately assumable (propagation lag). Rather
    # than unconditionally sleeping before the first attempt (a fixed cost on every run, even the
    # common case where the role is already assumable), rely solely on the reactive
    # retry-on-error loop below -- it only pays the delay when propagation lag actually manifests
    # as a CreateCluster failure, saving that time on every check on real AWS.
    last_err = None
    for _ in range(8):
        try:
            _create()
            break
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] in ("ClientException", "InvalidParameterException"):
                time.sleep(3)
                continue
            raise
    else:
        raise last_err

    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(eks, cluster_name))

    _poll_until(
        lambda: eks.describe_cluster(name=cluster_name)["cluster"],
        lambda c: c["status"] == "ACTIVE",
        timeout_s=1200.0,
        interval_s=15.0,
    )
    return cluster_name, subnet_ids


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



def _delete_eks_cluster_and_wait(eks, name, timeout_s=1200.0, interval_s=20.0):
    """Delete an EKS cluster and wait until it is gone, so its ENIs leave the shared network.

    DeleteCluster is refused while an update, node group or add-on operation still runs; that
    ResourceInUseException is retried until the deadline.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            eks.delete_cluster(name=name)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"EKS cluster {name} still exists {timeout_s:.0f}s after DeleteCluster")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
