"""topic-delete-nonexistent-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "topic-delete-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["kafka"]

# Prefix of the failure for a resource the target accepted but never brought to its ready state.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"

#: MSK's control-plane refusal for a topic the cluster does not hold (measured on real AWS; the
#: apostrophe is U+2019, not ASCII).
_TOPIC_NOT_FOUND_MESSAGE = "The requested resource doesn\u2019t exist."


def _never_ready(msg: str):
    """The verdict for a resource that never reached its ready state.

    Returns the exception rather than raising it, so a call site keeps its ``from exc`` chaining.
    """
    return AssertionError(f"{STATE_MARKER}: {msg}")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTopic for a topic name that never existed returns the control-plane NotFoundException
    (not the broker's UnknownTopicOrPartition, and not a silent success), while deleting a topic
    that does exist (positive control) removes it."""
    kafka = ctx.client("kafka")
    cluster_arn = _create_active_cluster(ctx, num_brokers=2)
    ghost_name = ctx.unique_name("sim2real-ghost-")

    code, message = _error(lambda: kafka.delete_topic(ClusterArn=cluster_arn, TopicName=ghost_name))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    expected = _TOPIC_NOT_FOUND_MESSAGE
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    names = [t["TopicName"] for t in kafka.list_topics(ClusterArn=cluster_arn).get("Topics", [])]
    assert ghost_name not in names, "DeleteTopic on a never-existing topic must not create a phantom entry"

    # Positive control: a topic that really exists is genuinely removed by DeleteTopic.
    real_name = ctx.unique_name("sim2real-real-")
    kafka.create_topic(ClusterArn=cluster_arn, TopicName=real_name, PartitionCount=1, ReplicationFactor=2)
    ctx.on_cleanup(lambda: _delete_topic_ignore_missing(kafka, cluster_arn, real_name))
    _wait_topic_status(ctx, cluster_arn, real_name, {"ACTIVE"}, timeout_s=180)
    kafka.delete_topic(ClusterArn=cluster_arn, TopicName=real_name)

    gone = _wait_topic_refused(kafka, cluster_arn, real_name, timeout_s=180)
    expected_gone = ("NotFoundException", _TOPIC_NOT_FOUND_MESSAGE)
    assert gone == expected_gone, (
        f"a topic that really existed must be gone after DeleteTopic: expected {expected_gone!r}, got {gone!r}"
    )


# ===== helpers =====

def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) it raises.

    A call that succeeds is itself the failure: raise AssertionError rather than return a code,
    so an over-permissive target reads as an accepted call and not as a code mismatch.
    """
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


_MANAGED_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]


def _delete_with_retry(fn, transient_code, timeout_s=180.0, interval_s=2.0):
    """Retry a delete through a transient DependencyViolation window.

    An MSK cluster's ENIs in this subnet detach AFTER DeleteCluster returns, not before, so a single
    attempt can be refused while the cluster's network interfaces are still being released.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == transient_code and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_own_network(ctx, count: int):
    """A VPC and `count` subnets in distinct AZs, created fresh — never adopted from a default VPC.

    A freshly provisioned account may not have a default VPC at all, so this check brings its
    own instead of assuming one. Registered for cleanup immediately: a failure between here and the
    cluster create must not strand this network.
    """
    import random

    ec2 = ctx.client("ec2")
    cidr_base = random.randrange(20, 250)
    vpc_id = ec2.create_vpc(
        CidrBlock=f"10.{cidr_base}.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _MANAGED_TAGS}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(
        lambda: _delete_with_retry(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id), "DependencyViolation")
    )
    # MSK's CreateClusterV2 refuses a VPC with DNS hostnames disabled (the default for a
    # non-default VPC): "VPC ... doesn't have DNS hostnames enabled" (measured on real AWS).
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    ).get("AvailabilityZones", [])
    if len(azs) < count:
        raise AssertionError(f"region has fewer than {count} available availability zones")

    subnet_ids = []
    for i, az in enumerate(azs[:count]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.{cidr_base}.{i}.0/24",
            AvailabilityZone=az["ZoneName"],
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _MANAGED_TAGS}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(
            lambda sid=subnet_id: _delete_with_retry(
                lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid), "DependencyViolation"
            )
        )
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _create_open_security_group(ctx, vpc_id: str, name: str) -> str:
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real kafka behavioral check",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _MANAGED_TAGS}],
    )["GroupId"]

    ctx.on_cleanup(
        lambda: _delete_with_retry(
            lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id), "DependencyViolation"
        )
    )
    return sg_id


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
    vpc_id, subnets = _create_own_network(ctx, num_brokers)
    default_sg = _create_open_security_group(ctx, vpc_id, ctx.unique_name("sim2real-msk-sg-"))
    versions = kafka.list_kafka_versions().get("KafkaVersions", [])
    if not versions:
        raise AssertionError("no Kafka versions available to create a test cluster")

    def _version_key(v):
        try:
            return tuple(int(p) for p in v["Version"].split("."))
        except ValueError:
            return (0,)

    # Try the newest available Kafka versions first, falling back to older ones: MSK sometimes
    # reserves the single newest version returned by ListKafkaVersions for a different broker
    # category (e.g. Express-only) and rejects "Standard" instance types like kafka.t3.small
    # with a BadRequestException ("Standard instance types are not supported for Kafka version
    # ..."), while the next-newest version supports them fine. Probe candidates newest-first via
    # the real CreateCluster call instead of assuming the newest entry is always usable.
    versions.sort(key=_version_key, reverse=True)
    # Standard brokers reject every DEPRECATED Kafka version.
    versions = [v for v in versions if v.get("Status") == "ACTIVE"]
    sg_ids = security_group_ids if security_group_ids is not None else ([default_sg] if default_sg else [])
    name = ctx.unique_name("sim2real-msk-")
    cluster_arn = None
    last_bad_request = None
    for v in versions[:6]:
        try:
            resp = kafka.create_cluster(
                ClusterName=name,
                KafkaVersion=v["Version"],
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


def _wait_topic_refused(kafka, cluster_arn, topic_name, timeout_s=180, interval_s=3):
    """Poll DescribeTopic until it is refused; return that refusal's (Code, Message).

    Raises AssertionError if the topic is still describable when the deadline passes.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            last = kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name).get("Status")
        except ClientError as e:
            return e.response["Error"].get("Code"), e.response["Error"].get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"topic {topic_name} still describable after {timeout_s}s (last status={last})")
        time.sleep(interval_s)


def _delete_topic_ignore_missing(kafka, cluster_arn, topic_name):
    # DeleteTopic refuses a topic that is still CREATING, so retry for a while.
    deadline = time.monotonic() + 300
    while True:
        try:
            kafka.delete_topic(ClusterArn=cluster_arn, TopicName=topic_name)
            return
        except ClientError as e:
            if "CREATING state" in e.response["Error"].get("Message", "") and time.monotonic() < deadline:
                time.sleep(10)
                continue
            if e.response["Error"]["Code"] != "NotFoundException":
                raise
            return


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. So wait (bounded) for the
# resource's ENIs to go, retry DependencyViolation inside the same window, and raise a final failure
# naming the ENIs still attached; every other error propagates. The window is shared by all of one
# check's network deletes and starts once the cluster is gone.
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
