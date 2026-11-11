"""scram-secret-operations-require-scram-enabled-active-cluster."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scram-secret-operations-require-scram-enabled-active-cluster"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

#: MSK's refusals for SCRAM-secret calls on a cluster without SASL/SCRAM.
#: While the cluster is CREATING the state is checked first for associate and list; disassociate
#: checks the authentication config first in every state.
_CREATING_ASSOCIATE_MSG = (
    "Invalid cluster state. Cluster must be in the ACTIVE, UPDATING, MAINTENANCE, HEALING, or "
    "REBOOTING_BROKER state to associate secrets."
)
_CREATING_LIST_MSG = (
    "Invalid cluster state. Cluster must be in the ACTIVE, UPDATING, MAINTENANCE, HEALING, or "
    "REBOOTING_BROKER state to list secrets."
)
_SCRAM_DISABLED_MSG = "SASL/SCRAM client authentication must be enabled for the cluster."


def _error(fn):
    """Call fn(); return the (Error.Code, Error.Message) it raises.

    A call that succeeds raises AssertionError, so an over-permissive target is not a code mismatch.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


_KAFKA_VERSION = "3.9.x"
_INSTANCE_TYPE = "kafka.t3.small"


def _account_id(ctx):
    if not hasattr(ctx, "_kafka_account_id"):
        ctx._kafka_account_id = ctx.client("sts").get_caller_identity()["Account"]
    return ctx._kafka_account_id




def _create_cluster(ctx, msk):
    """Create the check's own 2-broker PROVISIONED cluster in its own network; returns at once
    (state CREATING). The teardown deletes the cluster before the network it sits in."""
    vpc_id, subnet_ids = _create_own_network(ctx, 2)
    sg_id = _create_self_referencing_security_group(ctx, vpc_id, ctx.unique_name("sim2real-msk-sg-"))
    resp = msk.create_cluster_v2(
        ClusterName=ctx.unique_name("sim2real-behav-scram-"),
        Provisioned={
            "BrokerNodeGroupInfo": {
                "InstanceType": _INSTANCE_TYPE,
                "ClientSubnets": subnet_ids,
                "SecurityGroups": [sg_id],
                "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 1}},
            },
            "KafkaVersion": _KAFKA_VERSION,
            "NumberOfBrokerNodes": 2,
        },
        Tags={"sim2real:managed": "true"},
    )
    arn = resp["ClusterArn"]

    # The cluster teardown runs before the network teardown registered above it.
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(msk, arn))
    return arn, resp.get("State")


#: Cluster states in which MSK refuses DeleteCluster; teardown waits them out first.
_CLUSTER_BUSY_STATES = ("CREATING", "UPDATING", "REBOOTING_BROKER")


def _delete_cluster_and_wait(kafka, arn, settle_s=2700, gone_s=2700, interval_s=2):
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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_cluster_settled(ctx, msk, arn, timeout_s=2700, interval_s=1):
    """Poll DescribeClusterV2 until the cluster leaves CREATING; raise on timeout."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        state = msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["State"]
        if state != "CREATING":
            return state
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"cluster {arn} leaving CREATING: the run budget ended first; not graded")
            raise AssertionError(f"cluster {arn} still CREATING after {timeout_s}s")
        time.sleep(interval_s)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Every SCRAM-secret operation is refused on a cluster without SASL/SCRAM, CREATING or ACTIVE.

    Each refusal is a BadRequestException with the exact MSK message, never a 200 with per-item
    UnprocessedScramSecrets errors or an empty secret list.
    """
    msk = ctx.client("kafka")
    arn, created_state = _create_cluster(ctx, msk)
    assert created_state == "CREATING", f"CreateClusterV2 returned state {created_state!r}, expected CREATING"
    secret_arn = (
        f"arn:aws:secretsmanager:{ctx.region}:{_account_id(ctx)}:secret:AmazonMSK_"
        f"{ctx.unique_name('sim2real-behav-')}-AbCdEf"
    )

    # While CREATING, associate/list are refused on cluster state and disassociate on the missing
    # SASL/SCRAM config. A probe is graded against the CREATING message only while DescribeClusterV2
    # reports CREATING on both sides of it; once the cluster settles, the remaining probes take the
    # ACTIVE-state refusal. Always wait for the cluster to settle: a CREATING cluster cannot be deleted.
    def _state():
        return msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["State"]

    creating_probes = [
        ("associate", lambda: msk.batch_associate_scram_secret(ClusterArn=arn, SecretArnList=[secret_arn]),
         _CREATING_ASSOCIATE_MSG, _SCRAM_DISABLED_MSG),
        ("disassociate", lambda: msk.batch_disassociate_scram_secret(ClusterArn=arn, SecretArnList=[secret_arn]),
         _SCRAM_DISABLED_MSG, _SCRAM_DISABLED_MSG),
        ("list", lambda: msk.list_scram_secrets(ClusterArn=arn), _CREATING_LIST_MSG, None),
        ("disassociate (repeat)",
         lambda: msk.batch_disassociate_scram_secret(ClusterArn=arn, SecretArnList=[secret_arn]),
         _SCRAM_DISABLED_MSG, _SCRAM_DISABLED_MSG),
    ]
    try:
        for label, call, creating_msg, settled_msg in creating_probes:
            if _state() != "CREATING":
                break
            expected = ("BadRequestException", creating_msg)
            try:
                got = _error(call)
            except AssertionError:
                if _state() == "CREATING":
                    raise
                break  # the cluster settled during the call; the ACTIVE-state legs below grade it
            if got != expected and _state() != "CREATING":
                # The cluster settled during this call: MSK may answer with either state's refusal.
                allowed = [expected] + ([("BadRequestException", settled_msg)] if settled_msg else [])
                assert settled_msg is None or got in allowed, (
                    f"{label} while the cluster settled: expected one of {allowed!r}, got {got!r}"
                )
                break
            assert got == expected, f"{label} while CREATING: expected {expected!r}, got {got!r}"

        mid = _state()
        assert mid in ("CREATING", "ACTIVE"), (
            f"cluster state changed after rejected SCRAM-secret calls: expected CREATING or ACTIVE, got {mid}"
        )
    finally:
        state = _wait_cluster_settled(ctx, msk, arn)

    assert state == "ACTIVE", f"cluster settled {state} after the rejected SCRAM-secret calls, expected ACTIVE"

    expected = ("BadRequestException", _SCRAM_DISABLED_MSG)
    got = _error(lambda: msk.batch_associate_scram_secret(ClusterArn=arn, SecretArnList=[secret_arn]))
    assert got == expected, f"associate while ACTIVE: expected {expected!r}, got {got!r}"
    got = _error(lambda: msk.batch_disassociate_scram_secret(ClusterArn=arn, SecretArnList=[secret_arn]))
    assert got == expected, f"disassociate while ACTIVE: expected {expected!r}, got {got!r}"


_MANAGED_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]


def _delete_with_retry(fn, transient_code, timeout_s=180.0, interval_s=2.0):
    """Retry a delete through a transient DependencyViolation window.

    An MSK cluster's ENIs detach AFTER DeleteCluster returns, so a single attempt can fail.
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
    """Create a VPC and `count` subnets in distinct AZs; an account may have no default VPC.

    Each piece is registered for cleanup immediately so a later failure cannot strand it.
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
    # non-default VPC): "VPC ... doesn't have DNS hostnames enabled".
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


def _create_self_referencing_security_group(ctx, vpc_id: str, name: str) -> str:
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
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535, "UserIdGroupPairs": [{"GroupId": sg_id}]}
        ],
    )
    return sg_id


# A cluster in this VPC deletes asynchronously: its ENIs linger after DeleteCluster returns, so an
# immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Wait
# (bounded, one window shared by all network deletes) for the ENIs to go, then raise naming any left.
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
