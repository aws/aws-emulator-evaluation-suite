"""vpc-connection-malformed-subnet-config-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "vpc-connection-malformed-subnet-config-rejected"
GROUP = "overly-permissive"
SERVICES = ["kafka"]

_MANAGED_TAGS_MAP = {"sim2real:managed": "true"}
_MANAGED_TAGS = [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS_MAP.items()]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateVpcConnection with subnets outside the declared VpcId is a BadRequestException.

    No connection is left behind, while consistent subnet/VPC/security-group parameters against the
    same multi-VPC-enabled cluster create a connection that reaches AVAILABLE.
    """
    kafka = ctx.client("kafka")
    ec2 = ctx.client("ec2")

    vpc_id, subnet_ids, sg_id = _default_vpc_subnets(ctx)
    # Resolve the "wrong VPC" subnet before the ~80 min cluster + connectivity enable, so a
    # VpcLimitExceeded fails fast.
    other_subnet_id = _other_vpc_subnet(ctx, ec2, vpc_id)
    cluster_arn = _create_iam_auth_cluster(ctx, subnet_ids, sg_id)

    def _malformed_call():
        return kafka.create_vpc_connection(
            TargetClusterArn=cluster_arn,
            Authentication="SASL_IAM",
            VpcId=vpc_id,
            ClientSubnets=[other_subnet_id],
            SecurityGroups=[sg_id],
            Tags=_MANAGED_TAGS_MAP,
        )

    malformed_code, malformed_message, malformed_arn = _error_code_and_field(_malformed_call, "VpcConnectionArn")
    if malformed_arn:
        ctx.on_cleanup(lambda: kafka.delete_vpc_connection(Arn=malformed_arn))
    assert malformed_code == "BadRequestException", (
        f"expected BadRequestException for a subnet outside the declared VPC, got {malformed_code!r}"
    )
    # MSK checks the client subnet list against the cluster's before their VPC.
    assert malformed_message == "Specify the same number of client subnets as cluster subnets.", malformed_message

    before = {c["VpcConnectionArn"] for c in _list_vpc_connections(kafka) if c["TargetClusterArn"] == cluster_arn}
    assert not before, "a malformed CreateVpcConnection call must not leave a connection behind"

    good = kafka.create_vpc_connection(
        TargetClusterArn=cluster_arn,
        Authentication="SASL_IAM",
        VpcId=vpc_id,
        ClientSubnets=subnet_ids,
        SecurityGroups=[sg_id],
        Tags=_MANAGED_TAGS_MAP,
    )
    good_arn = good["VpcConnectionArn"]
    ctx.on_cleanup(lambda: _delete_vpc_connection(ctx, good_arn))
    info = _wait_vpc_connection_state(ctx, good_arn, {"AVAILABLE"}, timeout_s=900)
    assert info["State"] == "AVAILABLE", (
        f"expected the consistent-subnet VPC connection to reach AVAILABLE, got {info['State']!r}"
    )


def _error_code_and_field(fn, field):
    """(Error.Code, Error.Message, None) of the ClientError fn() raises, or (None, None, resp[field])."""
    try:
        resp = fn()
        return None, None, resp.get(field)
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", ""), None


def _list_vpc_connections(kafka):
    out = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = kafka.list_vpc_connections(**kwargs)
        out.extend(resp.get("VpcConnections", []))
        token = resp.get("NextToken")
        if not token:
            return out


def _other_vpc_subnet(ctx, ec2, exclude_vpc_id: str) -> str:
    """A subnet in a VPC the check creates, so it lies outside `exclude_vpc_id`."""
    other_vpc_id = ec2.create_vpc(
        CidrBlock="10.231.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _MANAGED_TAGS}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=other_vpc_id))
    other_subnet_id = ec2.create_subnet(
        VpcId=other_vpc_id,
        CidrBlock="10.231.1.0/24",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _MANAGED_TAGS}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=other_subnet_id))
    return other_subnet_id


def _default_vpc_subnets(ctx, min_count: int = 2):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())[:2]
    if len(subnet_ids) < 2:
        raise AssertionError("fewer than 2 AZ subnets available in the VPC to place MSK brokers")
    sgs = ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["SecurityGroups"]
    return vpc_id, subnet_ids, sgs[0]["GroupId"]


def _pick_kafka_version(kafka) -> str:
    versions = kafka.list_kafka_versions().get("KafkaVersions", [])
    if not versions:
        raise AssertionError("no Kafka versions returned by ListKafkaVersions")
    active = [v["Version"] for v in versions if v.get("Status") == "ACTIVE"]
    if "3.9.x" in active:  # recommended, still ZooKeeper; older Standard versions are refused
        return "3.9.x"
    return active[0] if active else versions[-1]["Version"]


def _create_iam_auth_cluster(ctx, subnet_ids, sg_id) -> str:
    kafka = ctx.client("kafka")
    name = ctx.unique_name("sim2real-vpcc-")
    version = _pick_kafka_version(kafka)
    # ConnectivityInfo (multi-VPC private connectivity) is not a member of CreateCluster's
    # BrokerNodeGroupInfo -- AWS rejects it with BadRequestException ("all vpcConnectivity
    # auth schemes must be disabled" at creation). It can only be turned on afterward, on an
    # ACTIVE cluster, via UpdateConnectivity (a rolling broker reboot).
    resp = kafka.create_cluster(
        ClusterName=name,
        KafkaVersion=version,
        NumberOfBrokerNodes=len(subnet_ids),
        BrokerNodeGroupInfo={
            # kafka.t3.small does not support multi-VPC private connectivity ("Multi-VPC private
            # connectivity is not supported on the broker instance type of the MSK cluster",
            # UpdateConnectivity BadRequestException) -- kafka.m5.large does.
            "InstanceType": "kafka.m5.large",
            "ClientSubnets": subnet_ids,
            "SecurityGroups": [sg_id],
        },
        ClientAuthentication={"Sasl": {"Iam": {"Enabled": True}}},
        EncryptionInfo={"EncryptionInTransit": {"ClientBroker": "TLS", "InCluster": True}},
        Tags=_MANAGED_TAGS_MAP,
    )
    arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, arn))
    _wait_cluster_state(ctx, arn, {"ACTIVE"}, timeout_s=2700)
    _enable_multi_vpc(ctx, arn)
    return arn


def _enable_multi_vpc(ctx, arn: str, timeout_s: float = 4800.0, interval_s: float = 30.0) -> None:
    """Enable multi-VPC SASL/IAM connectivity via UpdateConnectivity and poll the operation.

    It triggers a rolling broker reboot that AWS documents as "up to 30 minutes or more".
    """
    kafka = ctx.client("kafka")
    current_version = kafka.describe_cluster(ClusterArn=arn)["ClusterInfo"]["CurrentVersion"]
    resp = kafka.update_connectivity(
        ClusterArn=arn,
        CurrentVersion=current_version,
        ConnectivityInfo={"VpcConnectivity": {"ClientAuthentication": {"Sasl": {"Iam": {"Enabled": True}}}}},
    )
    op_arn = resp["ClusterOperationArn"]
    deadline = time.monotonic() + timeout_s
    info = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster_operation_v2(ClusterOperationArn=op_arn)["ClusterOperationInfo"]
        state = info.get("OperationState", "")
        if state.endswith(("COMPLETE", "COMPLETED", "FAILED")):
            break
        time.sleep(interval_s)
    else:
        raise AssertionError(f"UpdateConnectivity {op_arn} did not settle within {timeout_s}s")
    state = info.get("OperationState")
    assert state == "UPDATE_COMPLETE", (
        f"expected UpdateConnectivity to reach UPDATE_COMPLETE, got {state!r} ({info.get('ErrorInfo')})"
    )


def _delete_cluster(ctx, arn: str) -> None:
    kafka = ctx.client("kafka")
    try:
        kafka.delete_cluster(ClusterArn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NotFoundException":
            return
        raise
    _wait_cluster_deleted(ctx, arn, timeout_s=1800)


def _wait_cluster_state(ctx, arn, target_states, timeout_s=1800.0, interval_s=20.0):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster(ClusterArn=arn)["ClusterInfo"]
        last = info["State"]
        if last in target_states:
            return info
        if last == "FAILED":
            raise AssertionError(f"cluster entered FAILED state while waiting for {target_states}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster did not reach {target_states} within {timeout_s}s (last={last})")


def _wait_cluster_deleted(ctx, arn, timeout_s=1800.0, interval_s=20.0):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            kafka.describe_cluster(ClusterArn=arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError("cluster did not delete within timeout")


def _delete_vpc_connection(ctx, arn: str) -> None:
    kafka = ctx.client("kafka")
    try:
        kafka.delete_vpc_connection(Arn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NotFoundException":
            return
        raise
    # DeleteCluster is refused while the connection still exists, so wait until it is gone.
    deadline = time.monotonic() + 900.0
    while time.monotonic() < deadline:
        try:
            kafka.describe_vpc_connection(Arn=arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(15)
    raise AssertionError("vpc connection did not delete within timeout")


def _wait_vpc_connection_state(ctx, arn, target_states, timeout_s=900.0, interval_s=15.0):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_vpc_connection(Arn=arn)
        last = info["State"]
        if last in target_states:
            return info
        if last in {"FAILED", "REJECTED"}:
            raise AssertionError(f"vpc connection entered {last} while waiting for {target_states}")
        time.sleep(interval_s)
    raise AssertionError(f"vpc connection did not reach {target_states} within {timeout_s}s (last={last})")


# A cluster or VPC connection deletes asynchronously: its ENIs linger after the delete returns, so an
# immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Wait
# (bounded, one window shared by all network deletes) for the ENIs to go, then raise naming any left.
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
