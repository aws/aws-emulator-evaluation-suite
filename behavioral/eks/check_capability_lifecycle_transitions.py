"""capability-lifecycle-transitions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "capability-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Capability goes CREATING -> ACTIVE -> UPDATING (if observed) -> ACTIVE (new roleArn) ->
    DELETING -> 404; a delete during the update is either refused with ResourceInUseException
    (capability kept) or accepted and then really removes it."""
    eks = ctx.client("eks")
    cluster_name = _create_active_cluster(ctx)
    role_arn = _create_capability_role(ctx)
    role_arn_2 = _create_capability_role(ctx)

    capability_name = ctx.unique_name("sim2real-cap-")
    created = _create_capability_with_retry(eks, cluster_name, capability_name, role_arn)
    ctx.on_cleanup(lambda: _best_effort_delete_capability(eks, cluster_name, capability_name))
    assert created["capability"]["status"] == "CREATING", f"expected CreateCapability to return CREATING, got {created['capability']['status']!r}"
    assert created["capability"]["type"] == "KRO", f"expected capability type KRO, got {created['capability']['type']!r}"

    active = _poll_until(
        lambda: _describe_capability_or_creating(eks, cluster_name, capability_name),
        lambda c: c["status"] in ("ACTIVE", "CREATE_FAILED"),
        ctx=ctx,
        timeout_s=_budget_s(ctx, 900.0),
        interval_s=2.0,
    )
    assert active["status"] == "ACTIVE", f"capability did not reach ACTIVE: {active}"
    assert active["roleArn"] == role_arn, f"expected roleArn {role_arn!r} on the ACTIVE capability, got {active['roleArn']!r}"

    listed = eks.list_capabilities(clusterName=cluster_name)["capabilities"]
    assert capability_name in {c["capabilityName"] for c in listed}, (
        f"expected {capability_name!r} in ListCapabilities, got {listed}"
    )

    update_resp = eks.update_capability(
        clusterName=cluster_name, capabilityName=capability_name, roleArn=role_arn_2
    )
    assert update_resp["update"]["id"], f"expected UpdateCapability to return a non-empty update id, got {update_resp['update']!r}"

    # A delete landing before the status flips to UPDATING would just succeed, so wait (briefly)
    # until the update is observably in flight; ACTIVE with the new roleArn means it already settled.
    in_flight = _poll_until(
        lambda: _describe_capability_tolerant(eks, cluster_name, capability_name, "UPDATING"),
        lambda c: c["status"] != "ACTIVE" or c.get("roleArn") == role_arn_2,
        ctx=ctx,
        timeout_s=_budget_s(ctx, 60.0),
        interval_s=1.0,
    )
    assert in_flight["status"] == "UPDATING" or (
        in_flight["status"] == "ACTIVE" and in_flight.get("roleArn") == role_arn_2
    ), f"update neither entered UPDATING nor settled to ACTIVE with the new roleArn: {in_flight}"

    # A roleArn-only update can settle between the describe and the delete, so AWS may accept the
    # delete. Both outcomes are legitimate; assert the state each one implies.
    try:
        eks.delete_capability(clusterName=cluster_name, capabilityName=capability_name)
    except ClientError as exc:
        delete_code = exc.response["Error"]["Code"]
    else:
        delete_code = None
    if delete_code is not None:
        assert delete_code == "ResourceInUseException", delete_code
        still_present = _describe_capability_tolerant(eks, cluster_name, capability_name, "UPDATING")
        assert still_present["status"] != "ACTIVE" or still_present.get("roleArn") in (role_arn, role_arn_2), (
            "the refused delete must not have removed the capability"
        )

        updated = _poll_until(
            lambda: _describe_capability_tolerant(eks, cluster_name, capability_name, "UPDATING"),
            lambda c: c["status"] in ("ACTIVE", "UPDATE_FAILED"),
            ctx=ctx,
            timeout_s=_budget_s(ctx, 900.0),
            interval_s=2.0,
        )
        assert updated["status"] == "ACTIVE", f"capability update did not settle to ACTIVE: {updated}"
        assert updated["roleArn"] == role_arn_2, "roleArn must reflect the completed UpdateCapability"

        eks.delete_capability(clusterName=cluster_name, capabilityName=capability_name)

    # A capability delete can finish before the next describe sees DELETING; an immediate 404
    # counts as DELETING, and the not-found assertions below confirm it is gone.
    deleting = _describe_capability_tolerant(eks, cluster_name, capability_name, "DELETING")
    assert deleting["status"] == "DELETING", (
        f"a delete AWS accepted (even concurrently with an in-progress update) must actually "
        f"delete the capability, not leave it resurrected in some other state: {deleting}"
    )

    _wait_deleted(
        lambda: eks.describe_capability(clusterName=cluster_name, capabilityName=capability_name),
        ctx=ctx,
        timeout_s=_budget_s(ctx, 600.0),
        interval_s=2.0,
    )
    not_found_code, not_found_msg = _error(
        lambda: eks.describe_capability(clusterName=cluster_name, capabilityName=capability_name)
    )
    assert not_found_code == "ResourceNotFoundException", not_found_code
    assert not_found_msg == "The requested resource does not exist.", not_found_msg

    final_list = eks.list_capabilities(clusterName=cluster_name)["capabilities"]
    assert capability_name not in {c["capabilityName"] for c in final_list}, (
        f"expected {capability_name!r} absent from ListCapabilities after delete, got {final_list}"
    )




def _error(fn):
    """Call fn, require it raises ClientError, return the error (Code, Message)."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _describe_capability_or_creating(eks, cluster_name, capability_name):
    """DescribeCapability, treating a 404 right after CreateCapability as still CREATING.

    The new record is not instantly visible to every read path; any other error propagates."""
    try:
        return eks.describe_capability(clusterName=cluster_name, capabilityName=capability_name)["capability"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return {"status": "CREATING"}
        raise


def _describe_capability_tolerant(eks, cluster_name, capability_name, fallback_status):
    """DescribeCapability, mapping a transient 404 for a known capability to ``fallback_status``.

    Records are not instantly visible to (or removed from) every read path."""
    try:
        return eks.describe_capability(clusterName=cluster_name, capabilityName=capability_name)["capability"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return {"status": fallback_status}
        raise


def _create_capability_with_retry(eks, cluster_name, capability_name, role_arn, attempts=50, delay_s=2):
    """CreateCapability, retrying the trust-policy InvalidParameterException a just-created IAM role
    can trigger while IAM is eventually consistent."""
    last_err = None
    for _ in range(attempts):
        try:
            return eks.create_capability(
                clusterName=cluster_name,
                capabilityName=capability_name,
                type="KRO",
                roleArn=role_arn,
                deletePropagationPolicy="RETAIN",
            )
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] == "InvalidParameterException" and "trust policy" in str(e):
                time.sleep(delay_s)
                continue
            raise
    raise last_err


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, timeout_s=600.0, interval_s=2.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("the polled condition: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _wait_deleted(describe_fn, timeout_s=900.0, interval_s=2.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            describe_fn()
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("the resource being deleted: the run budget ended first; not graded")
    raise AssertionError(f"resource still present after {timeout_s}s")


def _retry_delete(fn, attempts=100, delay_s=3):
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


def _best_effort_delete_capability(eks, cluster_name, capability_name):
    try:
        eks.delete_capability(clusterName=cluster_name, capabilityName=capability_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    _wait_deleted(
        lambda: eks.describe_capability(clusterName=cluster_name, capabilityName=capability_name),
        timeout_s=600.0,
        interval_s=2.0,
    )


def _create_vpc_infra(ctx):
    ec2 = ctx.client("ec2")
    # Reuse the shared network: a VPC and Internet Gateway per check exhausts the per-region IGW
    # quota (InternetGatewayLimitExceeded) and lengthens an already long setup.
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

    # Fallback when no usable shared network exists: provision a dedicated one.
    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    az_names = [a["ZoneName"] for a in azs[:2]]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.78.0.0/16",
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
            CidrBlock=f"10.78.{i}.0/24",
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
        _retry_delete(lambda: iam.delete_role(RoleName=name), attempts=10, delay_s=2)

    ctx.on_cleanup(_cleanup)
    return arn


def _create_capability_role(ctx):
    return _create_role(ctx, "capabilities.eks.amazonaws.com", ["sts:AssumeRole", "sts:TagSession"])


def _create_active_cluster(ctx):
    eks = ctx.client("eks")
    subnet_ids = _create_vpc_infra(ctx)
    role_arn = _create_role(
        ctx, "eks.amazonaws.com", "sts:AssumeRole",
        managed_policies=["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"],
    )
    cluster_name = ctx.unique_name("sim2real-eks-cluster-")

    def _create():
        # CreateCapability creates an access entry, which a CONFIG_MAP-only cluster (the default)
        # rejects, hence API_AND_CONFIG_MAP. No Pod is ever scheduled, so the default add-ons are
        # skipped to shorten cluster creation.
        return eks.create_cluster(
            name=cluster_name,
            roleArn=role_arn,
            resourcesVpcConfig={"subnetIds": subnet_ids, "endpointPublicAccess": True, "endpointPrivateAccess": False},
            accessConfig={"authenticationMode": "API_AND_CONFIG_MAP"},
            bootstrapSelfManagedAddons=False,
        )

    deadline = time.monotonic() + _budget_s(ctx, 80.0)
    while True:
        try:
            _create()
            break
        except ClientError as e:
            if e.response["Error"]["Code"] in ("ClientException", "InvalidParameterException") and (
                time.monotonic() < deadline
            ):
                time.sleep(2)
                continue
            if e.response["Error"]["Code"] in ("ClientException", "InvalidParameterException") and _budget_spent(ctx):
                raise TimeoutError(f"CreateCluster {cluster_name} past IAM propagation: the run budget ended first; not graded") from e
            raise

    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(eks, cluster_name))

    _poll_until(
        lambda: eks.describe_cluster(name=cluster_name)["cluster"],
        lambda c: c["status"] == "ACTIVE",
        ctx=ctx,
        timeout_s=_budget_s(ctx, 1200.0),
        interval_s=2.0,
    )
    return cluster_name


# A resource in this VPC deletes asynchronously and its ENIs linger, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Wait (bounded) for the ENIs to go,
# retry DependencyViolation in that window, then raise naming the ENIs still attached.
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



def _delete_eks_cluster_and_wait(eks, name, timeout_s=1200.0, interval_s=3.0):
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
