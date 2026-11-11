"""reboot-broker-state-transition-through-rebooting."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "reboot-broker-state-transition-through-rebooting"
GROUP = "state-machine"
SERVICES = ["kafka"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RebootBroker moves the cluster ACTIVE -> REBOOTING_BROKER -> ACTIVE in DescribeClusterV2, and
    ListNodes shows the same broker ARNs/IDs before and after: restarted in place, not replaced."""
    cluster_arn, _subnets, _sg = _create_provisioned_cluster(ctx, num_brokers=2)
    kafka = ctx.client("kafka")

    nodes_before = _list_all_nodes(ctx, cluster_arn)
    broker_ids_before = sorted(
        str(int(n["BrokerNodeInfo"]["BrokerId"])) for n in nodes_before if "BrokerNodeInfo" in n
    )
    node_arns_before = sorted(n["NodeARN"] for n in nodes_before if "BrokerNodeInfo" in n)
    assert len(broker_ids_before) == 2, (
        f"expected a 2-broker cluster, ListNodes returned broker ids {broker_ids_before}"
    )

    target_broker_id = broker_ids_before[0]
    kafka.reboot_broker(ClusterArn=cluster_arn, BrokerIds=[target_broker_id])

    seen_states = []
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        state = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]["State"]
        seen_states.append(state)
        if seen_states and seen_states[-1] == "ACTIVE" and "REBOOTING_BROKER" in seen_states:
            break
        if state == "FAILED":
            raise AssertionError("cluster entered FAILED state during RebootBroker")
        time.sleep(5)
    else:
        raise AssertionError(f"cluster never completed the reboot transition; observed states={seen_states}")

    assert "REBOOTING_BROKER" in seen_states, (
        f"expected to observe the REBOOTING_BROKER state at least once during RebootBroker, "
        f"observed states={seen_states}"
    )
    assert seen_states[-1] == "ACTIVE", (
        f"expected the cluster to settle back to ACTIVE after the reboot, "
        f"last observed states={seen_states}"
    )

    nodes_after = _list_all_nodes(ctx, cluster_arn)
    broker_ids_after = sorted(
        str(int(n["BrokerNodeInfo"]["BrokerId"])) for n in nodes_after if "BrokerNodeInfo" in n
    )
    node_arns_after = sorted(n["NodeARN"] for n in nodes_after if "BrokerNodeInfo" in n)
    assert broker_ids_after == broker_ids_before, (
        f"broker identities changed across RebootBroker: before={broker_ids_before} "
        f"after={broker_ids_after} (broker should be restarted in place, not replaced)"
    )
    assert node_arns_after == node_arns_before, (
        f"broker node ARNs changed across RebootBroker: before={node_arns_before} "
        f"after={node_arns_after} (broker should be restarted in place, not replaced)"
    )


def _default_vpc_subnets_and_sg(ctx, num_azs):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to provision an MSK cluster in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < num_azs:
        raise AssertionError(f"shared network has fewer than {num_azs} AZ-distinct network subnets")
    sg = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]
    return subnet_ids[:num_azs], sg["GroupId"]


def _active_kafka_version(ctx):
    kafka = ctx.client("kafka")
    versions = kafka.list_kafka_versions().get("KafkaVersions", [])
    # Kafka 4.x is Express-brokers-only; standard (Provisioned) broker instance
    # types like kafka.t3.small are rejected for those versions, so restrict to
    # ACTIVE versions below the 4.x line.
    active = [
        v["Version"]
        for v in versions
        if v.get("Status") == "ACTIVE" and not v["Version"].startswith("4.")
    ]
    if not active:
        raise AssertionError("ListKafkaVersions returned no ACTIVE Kafka version below 4.x")
    return sorted(active, key=lambda s: [int(p) if p.isdigit() else p for p in s.split(".")])[-1]


def _wait_for_cluster_state(ctx, cluster_arn, target_states, timeout_s=1800, interval_s=20):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]
        last = info.get("State")
        if last in target_states:
            return info
        if last == "FAILED":
            raise AssertionError(f"cluster entered FAILED state while waiting for {target_states}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster never reached {target_states}; last observed state={last}")


def _wait_for_cluster_deleted(ctx, cluster_arn, timeout_s=1800, interval_s=20):
    from botocore.exceptions import ClientError

    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            kafka.describe_cluster_v2(ClusterArn=cluster_arn)
        except ClientError as err:
            if err.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_arn} was not deleted within {timeout_s}s")


def _create_provisioned_cluster(ctx, num_brokers=2):
    kafka = ctx.client("kafka")
    subnets, sg_id = _default_vpc_subnets_and_sg(ctx, num_brokers)
    kafka_version = _active_kafka_version(ctx)
    name = ctx.unique_name("sim2real-behav-msk-")
    resp = kafka.create_cluster_v2(
        ClusterName=name,
        Provisioned={
            "BrokerNodeGroupInfo": {
                "InstanceType": "kafka.m5.large",
                "ClientSubnets": subnets,
                "SecurityGroups": [sg_id],
                "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 1}},
            },
            "KafkaVersion": kafka_version,
            "NumberOfBrokerNodes": num_brokers,
        },
        Tags={"sim2real:managed": "true"},
    )
    cluster_arn = resp["ClusterArn"]

    def _cleanup():
        try:
            kafka.delete_cluster(ClusterArn=cluster_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
            return
        try:
            _wait_for_cluster_deleted(ctx, cluster_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    _wait_for_cluster_state(ctx, cluster_arn, {"ACTIVE"}, timeout_s=1800)
    return cluster_arn, subnets, sg_id


def _list_all_nodes(ctx, cluster_arn):
    kafka = ctx.client("kafka")
    nodes = []
    token = None
    while True:
        kwargs = {"ClusterArn": cluster_arn}
        if token:
            kwargs["NextToken"] = token
        resp = kafka.list_nodes(**kwargs)
        nodes.extend(resp.get("NodeInfoList", []))
        token = resp.get("NextToken")
        if not token:
            break
    return nodes


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
