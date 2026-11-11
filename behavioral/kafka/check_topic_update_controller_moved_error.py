"""topic-update-controller-moved-error."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "topic-update-controller-moved-error"
GROUP = "error-semantics"
SERVICES = ["kafka"]

# Marks a failure where the target accepted a state transition but never converged, so it is
# graded as a failure rather than an environment error.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"

_REPLICATION_FACTOR = 3


def _never_ready(msg: str):
    """The verdict for a resource that never reached its ready state.

    Returns the exception rather than raising it, so a call site keeps its ``from exc`` chaining.
    """
    return AssertionError(f"{STATE_MARKER}: {msg}")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """While brokers of a 3-broker cluster reboot one at a time, UpdateTopic on an RF-3 topic is
    rejected with the exact BadRequestException naming the broker shortfall (or the topic still
    UPDATING); once the cluster is ACTIVE again the same update succeeds."""
    kafka = ctx.client("kafka")
    cluster_arn = _create_active_cluster(ctx, num_brokers=3)
    topic_name = ctx.unique_name("sim2real-ctrl-")
    kafka.create_topic(
        ClusterArn=cluster_arn, TopicName=topic_name, PartitionCount=1, ReplicationFactor=_REPLICATION_FACTOR
    )
    ctx.on_cleanup(lambda: _delete_topic_ignore_missing(ctx, cluster_arn, topic_name))
    _wait_topic_status(ctx, cluster_arn, topic_name, {"ACTIVE"}, timeout_s=180)

    # BrokerId is modeled as a double, so str() on the raw value gives "1.0", which RebootBroker
    # rejects as BadRequestException("Invalid broker id"); it wants "1".
    broker_ids = [
        int(n["BrokerNodeInfo"]["BrokerId"]) for n in kafka.list_nodes(ClusterArn=cluster_arn).get("NodeInfoList", [])
    ]
    assert broker_ids, "expected at least one broker node to reboot"
    # RebootBroker accepts one broker per call ("Too many brokers specified. Specify only one
    # broker id."), so the reboots are rolled through one call per broker.
    pending_brokers = [str(b) for b in broker_ids]
    kafka.reboot_broker(ClusterArn=cluster_arn, BrokerIds=[pending_brokers.pop(0)])

    rejections = []  # (cluster state, error code, error message)
    partitions = 1
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        state = kafka.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]["State"]
        if state == "ACTIVE" and pending_brokers:
            try:
                kafka.reboot_broker(ClusterArn=cluster_arn, BrokerIds=[pending_brokers[0]])
                pending_brokers.pop(0)
            except ClientError:
                pass  # the previous reboot's cluster operation may still be draining; retry next tick
        if state == "ACTIVE" and rejections and not pending_brokers:
            break
        partitions += 1
        try:
            kafka.update_topic(ClusterArn=cluster_arn, TopicName=topic_name, PartitionCount=partitions)
            rejected = False
        except ClientError as exc:
            err = exc.response.get("Error", {})
            rejections.append((state, err.get("Code"), err.get("Message")))
            rejected = True
        if state == "ACTIVE" and not rejected and not pending_brokers:
            break
        time.sleep(1)

    # Settle before grading so the cluster is left ACTIVE either way.
    _wait_cluster_state(ctx, cluster_arn, {"ACTIVE"}, timeout_s=600)
    final = _wait_topic_status(ctx, cluster_arn, topic_name, {"ACTIVE"}, timeout_s=180)

    # An update accepted between reboots leaves the topic UPDATING, so racing calls are refused for
    # that reason instead of the broker shortfall.
    shortfall = (
        "BadRequestException",
        f"Replication factor: {_REPLICATION_FACTOR} larger than available brokers: {len(broker_ids) - 1}.",
    )
    still_updating = ("BadRequestException", "You can't update a topic in UPDATING state.")
    assert rejections, "broker reboot completed without exposing any UpdateTopic rejection in this run"
    for state, code, message in rejections:
        assert (code, message) in (shortfall, still_updating), (
            f"unexpected UpdateTopic rejection during broker reboot (cluster {state}): {code} {message!r}; "
            f"expected {shortfall} or {still_updating}"
        )
    assert any((code, message) == shortfall for _, code, message in rejections), (
        f"no UpdateTopic rejection named the rebooting broker's shortfall {shortfall}; got {set(rejections)}"
    )

    # Positive control: once settled, an UpdateTopic on the same topic succeeds cleanly.
    kafka.update_topic(ClusterArn=cluster_arn, TopicName=topic_name, PartitionCount=final["PartitionCount"] + 1)
    settled = _wait_topic_status(ctx, cluster_arn, topic_name, {"ACTIVE"}, timeout_s=180)
    assert settled["PartitionCount"] == final["PartitionCount"] + 1


def _provision_network(ctx, count=2):
    """A private VPC, one subnet per availability zone and a security group for the broker ENIs,
    created and torn down by the check itself."""
    ec2 = ctx.client("ec2")

    def _tags(resource_type):
        return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-msk-net-")}]}]

    vpc_id = ec2.create_vpc(CidrBlock="10.98.0.0/16", TagSpecifications=_tags("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    azs = [a["ZoneName"] for a in ec2.describe_availability_zones()["AvailabilityZones"][:count]]
    if len(azs) < count:
        raise AssertionError(f"region does not have {count} availability zones available to place MSK broker ENIs")
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.98.{i}.0/24", AvailabilityZone=az, TagSpecifications=_tags("subnet")
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)

    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=ctx.unique_name("sim2real-msk-sg-"),
        Description="sim2real topic-update controller test",
        TagSpecifications=_tags("security-group"),
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
    return subnet_ids, sg_id


def _wait_cluster_state(ctx, cluster_arn, target_states, timeout_s=1800, interval_s=20):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        last_state = kafka.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]["State"]
        if last_state in target_states:
            return last_state
        time.sleep(interval_s)
    raise _never_ready(
        f"cluster did not reach {target_states} within {timeout_s}s (last state={last_state})",
    )


#: Cluster states in which MSK refuses DeleteCluster; teardown waits them out first.
_CLUSTER_BUSY_STATES = ("CREATING", "UPDATING", "REBOOTING_BROKER")


def _delete_cluster_and_wait(kafka, arn, settle_s=2700, gone_s=2700, interval_s=20):
    """Teardown: wait for the cluster to settle (MSK refuses DeleteCluster while it is CREATING or
    applying an operation), delete it, and poll until it is gone so the network teardown can
    follow. Raises on either timeout; NotFound at any point means the cluster is already gone."""
    deadline = time.monotonic() + settle_s
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
            raise AssertionError(f"cluster {arn} still {state} after {settle_s}s; DeleteCluster not issued")
        time.sleep(interval_s)
    if state != "DELETING":
        try:
            kafka.delete_cluster(ClusterArn=arn)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NotFoundException":
                raise
    deadline = time.monotonic() + gone_s
    while True:
        try:
            state = kafka.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["State"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"cluster {arn} still {state} {gone_s}s after DeleteCluster")
        time.sleep(interval_s)


def _create_active_cluster(ctx, num_brokers=2, security_group_ids=None, instance_type="kafka.t3.small", timeout_s=1800):
    kafka = ctx.client("kafka")
    subnets, default_sg = _provision_network(ctx, count=num_brokers)
    versions = kafka.list_kafka_versions().get("KafkaVersions", [])
    if not versions:
        raise AssertionError("no Kafka versions available to create a test cluster")

    # DEPRECATED versions cannot back a new cluster; use the full list only if none is ACTIVE.
    candidates = [v["Version"] for v in versions if v.get("Status") == "ACTIVE"] or [
        v["Version"] for v in versions
    ]

    sg_ids = security_group_ids if security_group_ids is not None else ([default_sg] if default_sg else [])
    name = ctx.unique_name("sim2real-msk-")
    cluster_arn = None
    last_bad_request = None
    # MSK rejects Standard instance types for some versions ("Standard instance types are not
    # supported for Kafka version ..."), which ListKafkaVersions does not reveal, so try each.
    for version in candidates:
        try:
            resp = kafka.create_cluster(
                ClusterName=name,
                KafkaVersion=version,
                NumberOfBrokerNodes=num_brokers,
                BrokerNodeGroupInfo={
                    "InstanceType": instance_type,
                    "ClientSubnets": subnets,
                    "SecurityGroups": sg_ids,
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
            f"no available Kafka version supports instance type {instance_type} via CreateCluster: {last_bad_request}"
        )

    # The cluster teardown runs before the network teardown registered above it.
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(kafka, cluster_arn))
    state = _wait_cluster_state(ctx, cluster_arn, {"ACTIVE", "FAILED"}, timeout_s=timeout_s)
    if state != "ACTIVE":
        raise AssertionError(f"cluster entered {state} instead of ACTIVE")
    return cluster_arn


def _wait_topic_status(ctx, cluster_arn, topic_name, target_statuses, timeout_s=180, interval_s=3):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name)
        if last.get("Status") in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"topic {topic_name} never reached {target_statuses}, last={last}")


def _delete_topic_ignore_missing(ctx, cluster_arn, topic_name):
    kafka = ctx.client("kafka")
    try:
        kafka.delete_topic(ClusterArn=cluster_arn, TopicName=topic_name)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("NotFoundException", "UnknownTopicOrPartitionException"):
            raise


# DeleteCluster returns while the broker ENIs still sit in the subnets and security group, so
# network deletes wait (bounded, one shared window) for the ENIs and retry DependencyViolation.
_NET_TEARDOWN_S = 1800.0
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
