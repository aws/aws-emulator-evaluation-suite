"""update-security-server-enforced."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-security-server-enforced"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

_PROVISIONED_INSTANCE_TYPE = "kafka.t3.small"


def _client_error(fn):
    """Call fn() and return its ClientError's (code, message); a call that succeeds fails the check."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be rejected with a ClientError, but it succeeded")


_NOT_FOUND_MESSAGE = "The requested resource doesn\u2019t exist."


def _bogus_cluster_arn(ctx):
    """A well-formed MSK cluster ARN, in this account, that cannot exist."""
    return (
        f"arn:aws:kafka:{ctx.region}:{ctx.account}:cluster/"
        f"{ctx.unique_name('sim2real-behav-nonexistent-')}/"
        "00000000-0000-0000-0000-000000000000-1"
    )


def _provision_network(ctx, count=2):
    """A private VPC, one subnet per availability zone and a security group for the broker ENIs,
    created and torn down by the check itself."""
    ec2 = ctx.client("ec2")

    def _tags(resource_type):
        return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-msk-net-")}]}]

    vpc_id = ec2.create_vpc(CidrBlock="10.97.0.0/16", TagSpecifications=_tags("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", lambda: _teardown_deadline(ctx), VpcId=vpc_id))

    azs = [a["ZoneName"] for a in ec2.describe_availability_zones()["AvailabilityZones"][:count]]
    if len(azs) < count:
        raise AssertionError(f"region does not have {count} availability zones available to place MSK broker ENIs")
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.97.{i}.0/24", AvailabilityZone=az, TagSpecifications=_tags("subnet")
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(
            lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", lambda: _teardown_deadline(ctx), SubnetId=sid)
        )
        subnet_ids.append(subnet_id)

    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=ctx.unique_name("sim2real-msk-sg-"),
        Description="sim2real update-security cluster test",
        TagSpecifications=_tags("security-group"),
    )["GroupId"]
    ctx.on_cleanup(
        lambda: _delete_net(ec2, "delete_security_group", lambda: _teardown_deadline(ctx), GroupId=sg_id)
    )
    return subnet_ids, sg_id


def _poll_cluster_leaves_active(msk, cluster_arn, timeout_s=120.0, interval_s=3.0):
    """The cluster's ClusterInfo at its first read whose State is not ACTIVE; the update's
    state change is asynchronous, so the first read after the call may still be ACTIVE."""
    deadline = time.monotonic() + timeout_s
    while True:
        info = msk.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]
        if info["State"] != "ACTIVE" or time.monotonic() >= deadline:
            return info
        time.sleep(interval_s)


def _wait_cluster_state(ctx, cluster_arn, target_states, timeout_s=1800, interval_s=20):
    msk = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        last_state = msk.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]["State"]
        if last_state in target_states:
            return last_state
        time.sleep(interval_s)
    raise AssertionError(f"cluster did not reach {target_states} within {timeout_s}s (last state={last_state})")


def _wait_operation_state(ctx, op_arn, target_states, timeout_s=1800, interval_s=20):
    msk = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = msk.describe_cluster_operation(ClusterOperationArn=op_arn)["ClusterOperationInfo"]
        if last["OperationState"] in target_states:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"cluster operation did not reach {target_states} within {timeout_s}s (last={last})")


_CLUSTER_NAME_PREFIX = "sim2real-behav-security-"


#: Cluster states in which MSK refuses DeleteCluster; teardown waits them out first.
_CLUSTER_BUSY_STATES = ("CREATING", "UPDATING", "REBOOTING_BROKER")


def _delete_cluster_and_wait(kafka, arn, deadline_fn, interval_s=20):
    """Teardown: wait for the cluster to settle (MSK refuses DeleteCluster while it is CREATING or
    applying an operation), delete it, and poll until it is gone so the network teardown can
    follow, all to the run's shared cleanup deadline. Raises at the deadline; NotFound at any point
    means the cluster is already gone."""
    deadline = deadline_fn()
    while True:
        try:
            state = kafka.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["State"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NotFoundException":
                return
            raise
        if state not in _CLUSTER_BUSY_STATES:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"cluster {arn} still {state} at the cleanup deadline; DeleteCluster not issued")
        time.sleep(interval_s)
    if state != "DELETING":
        try:
            kafka.delete_cluster(ClusterArn=arn)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NotFoundException":
                raise
    while True:
        try:
            state = kafka.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["State"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"cluster {arn} still {state} at the cleanup deadline after DeleteCluster")
        time.sleep(interval_s)


def _create_active_cluster(ctx, num_brokers=2, timeout_s=3000):
    """A real, minimal ACTIVE MSK cluster: the positive control proving UpdateSecurity has
    something to actually apply to. Teardown waits for the cluster to settle, deletes it and polls
    until it is gone; the network teardown then waits for the broker ENIs to leave."""
    msk = ctx.client("kafka")
    subnets, sg_id = _provision_network(ctx, count=num_brokers)
    cluster_arn = None
    versions = msk.list_kafka_versions().get("KafkaVersions", [])
    if not versions:
        raise AssertionError("no Kafka versions available to create a test cluster")

    def _version_key(v):
        try:
            return tuple(int(p) for p in v["Version"].split("."))
        except ValueError:
            return (0,)

    # Newest-first, falling back: MSK sometimes reserves the newest catalog entries for
    # Express-only brokers and rejects "Standard" instance types like kafka.t3.small.
    versions.sort(key=_version_key, reverse=True)
    # Standard brokers reject every DEPRECATED Kafka version.
    versions = [v for v in versions if v.get("Status") == "ACTIVE"]
    name = ctx.unique_name(_CLUSTER_NAME_PREFIX)
    last_bad_request = None
    for v in versions[:6]:
        try:
            resp = msk.create_cluster(
                ClusterName=name,
                KafkaVersion=v["Version"],
                NumberOfBrokerNodes=num_brokers,
                BrokerNodeGroupInfo={
                    "InstanceType": _PROVISIONED_INSTANCE_TYPE,
                    "ClientSubnets": subnets,
                    "SecurityGroups": [sg_id] if sg_id else [],
                    "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 1}},
                },
                Tags={"sim2real:managed": "true"},
            )
            cluster_arn = resp["ClusterArn"]
            break
        except ClientError as e:
            msg = e.response["Error"].get("Message", "")
            if e.response["Error"]["Code"] == "BadRequestException" and "not supported for Kafka version" in msg:
                last_bad_request = e
                continue
            raise
    if cluster_arn is None:
        raise AssertionError(
            f"no available Kafka version supports {_PROVISIONED_INSTANCE_TYPE} via CreateCluster: {last_bad_request}"
        )

    ctx.on_cleanup(lambda: _delete_cluster_and_wait(msk, cluster_arn, lambda: _teardown_deadline(ctx)))

    state = _wait_cluster_state(ctx, cluster_arn, {"ACTIVE", "FAILED"}, timeout_s=timeout_s)
    if state != "ACTIVE":
        raise AssertionError(f"cluster entered {state} instead of ACTIVE")
    return cluster_arn


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateSecurity on an ACTIVE cluster runs an UPDATING operation to UPDATE_COMPLETE and applies the
    new ClientBroker setting, while both forms for a missing cluster fail with NotFoundException and its
    exact message."""
    msk = ctx.client("kafka")

    real_arn = _create_active_cluster(ctx)
    before = msk.describe_cluster(ClusterArn=real_arn)["ClusterInfo"]
    version = before["CurrentVersion"]
    current_client_broker = before["EncryptionInfo"]["EncryptionInTransit"]["ClientBroker"]
    new_client_broker = next(v for v in ("TLS", "TLS_PLAINTEXT", "PLAINTEXT") if v != current_client_broker)

    resp = msk.update_security(
        ClusterArn=real_arn,
        CurrentVersion=version,
        EncryptionInfo={"EncryptionInTransit": {"ClientBroker": new_client_broker}},
    )
    assert resp.get("ClusterOperationArn"), "positive control: UpdateSecurity on a real ACTIVE cluster must succeed"
    mid = _poll_cluster_leaves_active(msk, real_arn)
    assert mid["State"] == "UPDATING", (
        f"positive control: expected State UPDATING after UpdateSecurity, got {mid['State']}"
    )

    op = _wait_operation_state(ctx, resp["ClusterOperationArn"], {"UPDATE_COMPLETE", "UPDATE_FAILED"})
    assert op["OperationState"] == "UPDATE_COMPLETE", f"positive control: security update did not complete: {op}"
    after = _wait_cluster_state(ctx, real_arn, {"ACTIVE", "FAILED"})
    assert after == "ACTIVE", f"positive control: cluster ended {after} instead of ACTIVE after the security update"
    applied = msk.describe_cluster(ClusterArn=real_arn)["ClusterInfo"]["EncryptionInfo"]["EncryptionInTransit"]
    assert applied["ClientBroker"] == new_client_broker, (
        f"positive control: expected ClientBroker {new_client_broker} after the update, got {applied['ClientBroker']}"
    )

    ghost = _bogus_cluster_arn(ctx)

    auth = _client_error(
        lambda: msk.update_security(
            ClusterArn=ghost,
            CurrentVersion="1",
            ClientAuthentication={
                "Sasl": {"Scram": {"Enabled": True}},
                "Unauthenticated": {"Enabled": False},
            },
        )
    )
    assert auth == ("NotFoundException", _NOT_FOUND_MESSAGE), (
        f"ClientAuthentication form: expected NotFoundException {_NOT_FOUND_MESSAGE!r}, got {auth}"
    )

    encryption = _client_error(
        lambda: msk.update_security(
            ClusterArn=ghost,
            CurrentVersion="1",
            EncryptionInfo={"EncryptionInTransit": {"ClientBroker": "PLAINTEXT"}},
        )
    )
    assert encryption == ("NotFoundException", _NOT_FOUND_MESSAGE), (
        f"EncryptionInfo form: expected NotFoundException {_NOT_FOUND_MESSAGE!r}, got {encryption}"
    )

    described = _client_error(lambda: msk.describe_cluster(ClusterArn=ghost))
    assert described == ("NotFoundException", _NOT_FOUND_MESSAGE), (
        f"DescribeCluster: expected NotFoundException {_NOT_FOUND_MESSAGE!r}, got {described}"
    )


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes: a cluster or endpoint in
# this VPC deletes asynchronously, so its ENIs can still hold the subnet or security group and an
# immediate delete fails with DependencyViolation. The ENI wait and the DependencyViolation retries
# run to the run's one cleanup deadline, shared with the cluster teardown; a delete still refused
# then raises, naming the ENIs still attached.
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
#: The suite's cleanup budget; every teardown of one run shares a single deadline inside it.
_CLEANUP_BUDGET_S = 1800.0


def _teardown_deadline(ctx) -> float:
    """The run's one cleanup deadline, started by the first teardown that asks for it."""
    if getattr(ctx, "_kafka_teardown_deadline", None) is None:
        ctx._kafka_teardown_deadline = time.monotonic() + _CLEANUP_BUDGET_S
    return ctx._kafka_teardown_deadline


def _delete_net(client, op, deadline_fn, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    deadline = deadline_fn()
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
                        f"{op}({ident}): DependencyViolation at the cleanup deadline; "
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
