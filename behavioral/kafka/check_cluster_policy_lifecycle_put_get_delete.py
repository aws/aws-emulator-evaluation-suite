"""cluster-policy-lifecycle-put-get-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-policy-lifecycle-put-get-delete"
GROUP = "state-machine"
SERVICES = ["kafka"]

# Prefixes the failure of a resource the target accepted but never converged to its ready state,
# so it reads as a state-machine failure rather than a connection or not-implemented error.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


def _never_ready(msg: str):
    """The verdict for a resource that never reached its ready state.

    Returns the exception rather than raising it, so a call site keeps its ``from exc`` chaining.
    """
    return AssertionError(f"{STATE_MARKER}: {msg}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutClusterPolicy installs a resource policy visible via GetClusterPolicy;
    DeleteClusterPolicy removes it so a subsequent GetClusterPolicy reports none attached."""
    kafka = ctx.client("kafka")
    cluster_arn = _create_active_cluster(ctx, num_brokers=2)
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "sim2realAllowDescribe",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kafka:DescribeClusterV2",
                "Resource": cluster_arn,
            }
        ],
    }
    kafka.put_cluster_policy(ClusterArn=cluster_arn, Policy=json.dumps(policy_doc))

    got = kafka.get_cluster_policy(ClusterArn=cluster_arn)
    stored = json.loads(got["Policy"])
    assert stored["Statement"][0]["Sid"] == "sim2realAllowDescribe", (
        f"expected Sid sim2realAllowDescribe, got {stored['Statement'][0].get('Sid')}"
    )
    assert stored["Statement"][0]["Action"] == "kafka:DescribeClusterV2", (
        f"expected Action kafka:DescribeClusterV2, got {stored['Statement'][0].get('Action')}"
    )

    kafka.delete_cluster_policy(ClusterArn=cluster_arn)
    code, message = _error_of(lambda: kafka.get_cluster_policy(ClusterArn=cluster_arn))
    assert code == "NotFoundException", f"expected NotFoundException after delete, got {code}"
    assert message == "The requested resource doesn\u2019t exist.", f"GetClusterPolicy message: {message!r}"


def _error_of(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")


def _gone(fn) -> bool:
    """True once fn() raises NotFoundException, False while it succeeds; other errors raise."""
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] == "NotFoundException":
            return True
        raise
    return False


def _pick_subnets_and_sg(ctx, count=2):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    seen_az, chosen = set(), []
    for s in subnets:
        if s["AvailabilityZone"] not in seen_az:
            seen_az.add(s["AvailabilityZone"])
            chosen.append(s["SubnetId"])
        if len(chosen) >= count:
            break
    if len(chosen) < count:
        raise AssertionError("not enough distinct-AZ subnets in the shared network to create an MSK test cluster")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"] if sgs else None
    return chosen, sg_id


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


def _create_active_cluster(ctx, num_brokers=2, security_group_ids=None, instance_type="kafka.t3.small", timeout_s=1800):
    kafka = ctx.client("kafka")
    subnets, default_sg = _pick_subnets_and_sg(ctx, count=num_brokers)
    versions = kafka.list_kafka_versions().get("KafkaVersions", [])
    if not versions:
        raise AssertionError("no Kafka versions available to create a test cluster")

    def _version_key(v):
        # ZooKeeper versions before KRaft ones, then newest first; a "x" patch level sorts high.
        parts = v["Version"].split(".")
        numbers = tuple(int(p) if p.isdigit() else 99 for p in parts[:3])
        return ("kraft" not in parts, numbers)

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

    def _cleanup():
        try:
            _wait_cluster_state(ctx, cluster_arn, {"ACTIVE", "FAILED"}, timeout_s=timeout_s)
        except AssertionError:
            pass
        try:
            kafka.delete_cluster(ClusterArn=cluster_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if _gone(lambda: kafka.describe_cluster(ClusterArn=cluster_arn)):
                return
            time.sleep(15)
        raise AssertionError(f"cluster {cluster_arn} still exists {timeout_s}s after DeleteCluster")

    ctx.on_cleanup(_cleanup)
    state = _wait_cluster_state(ctx, cluster_arn, {"ACTIVE", "FAILED"}, timeout_s=timeout_s)
    if state != "ACTIVE":
        raise AssertionError(f"cluster entered {state} instead of ACTIVE")
    return cluster_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
