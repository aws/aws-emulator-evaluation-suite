"""channel-delete-nonexistent-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "channel-delete-nonexistent-rejected"
GROUP = "overly-permissive"
SERVICES = ["kafka"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteChannel for a well-formed but never-created channel ARN on an Express cluster fails with
    BadRequestException and its exact message, and ListChannels shows no channel before or after."""
    kafka = ctx.client("kafka")
    cluster_arn = _create_express_cluster(ctx)

    # Positive control: the cluster is real, Express-capable, and channel APIs work.
    listed = kafka.list_channels(ClusterArn=cluster_arn)
    assert listed.get("Channels", []) == [], f"expected no channels yet, got {listed.get('Channels')}"

    cluster_name = cluster_arn.split("cluster/")[1].split("/")[0]
    fake_channel_arn = (
        f"arn:aws:kafka:{ctx.region}:{cluster_arn.split(':')[4]}:"
        f"channel/{cluster_name}/{ctx.unique_name('never-created-')}/{uuid.uuid4()}"
    )

    code, message = _error_code(
        lambda: kafka.delete_channel(ChannelArn=fake_channel_arn, ClusterArn=cluster_arn)
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert message == "The specified link ARN isn\u2019t valid. Specify a valid link ARN, and try again.", (
        f"DeleteChannel rejection message: {message!r}"
    )

    # Effect absent: no channel exists on the cluster before or after the failed delete.
    after = kafka.list_channels(ClusterArn=cluster_arn)
    assert after.get("Channels", []) == [], f"expected no channels after rejected delete, got {after.get('Channels')}"


def _pick_subnets_multi_az(ctx, count=3):
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
        raise AssertionError(
            f"fewer than {count} distinct-AZ subnets in the shared network; Express brokers require {count} AZs"
        )
    return chosen


def _wait_cluster_state(ctx, cluster_arn, target_states, timeout_s=1800, interval_s=20):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        last_state = kafka.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]["State"]
        if last_state in target_states:
            return last_state
        time.sleep(interval_s)
    raise AssertionError(f"cluster did not reach {target_states} within {timeout_s}s (last state={last_state})")


def _create_express_cluster(ctx, timeout_s=3300):
    kafka = ctx.client("kafka")
    subnets = _pick_subnets_multi_az(ctx, count=3)
    versions = kafka.list_kafka_versions().get("KafkaVersions", [])
    if not versions:
        raise AssertionError("no Kafka versions available to create a test cluster")

    def _key(v):
        parts = v["Version"].split(".")
        # CreateClusterV2's rejection names the Express-capable families explicitly: "Valid
        # values: [3.8.x, 3.9.x.kraft, 4.2.x.kraft]" -- each is a KRaft build or newer than the
        # versions that reject Express, so KRaft builds rank first, then newest first.
        is_kraft = parts[-1] == "kraft"
        numeric = tuple(int(p) for p in parts if p.isdigit())
        return (is_kraft, numeric)

    versions.sort(key=_key, reverse=True)
    # Express brokers reject every DEPRECATED Kafka version.
    versions = [v for v in versions if v.get("Status") == "ACTIVE"]
    # The 3.6.x family can accept Express brokers but not the Channels API: "Channels are not
    # supported on Apache Kafka version 3.6.x." Excluding it keeps the long cluster-create cycle
    # below from being spent on a version that can never serve the Channels API.
    versions = [v for v in versions if not v["Version"].startswith("3.6")]
    if not versions:
        raise AssertionError("no Kafka version left after excluding the Channels-incompatible 3.6.x family")
    name = ctx.unique_name("sim2real-mskx-")
    # Express broker instance types are only accepted through the CreateClusterV2 API; probe
    # candidates newest-first via the real call, since the single newest ListKafkaVersions entry
    # is sometimes reserved for a different broker category and rejects "Express" instance types
    # too ("Express instance types are not supported for Kafka version ...").
    cluster_arn = None
    last_bad_request = None
    for v in versions[:6]:
        try:
            resp = kafka.create_cluster_v2(
                ClusterName=name,
                Tags={"sim2real:managed": "true"},
                Provisioned={
                    "KafkaVersion": v["Version"],
                    "NumberOfBrokerNodes": 3,
                    "BrokerNodeGroupInfo": {
                        # Express brokers manage their own storage; CreateClusterV2 rejects an
                        # explicit StorageInfo for this instance type with a BadRequestException.
                        "InstanceType": "express.m7g.large",
                        "ClientSubnets": subnets,
                    },
                },
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
            f"no available Kafka version supports Express instance types via CreateClusterV2: {last_bad_request}"
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
            try:
                kafka.describe_cluster(ClusterArn=cluster_arn)
            except ClientError as e:
                if e.response["Error"]["Code"] == "NotFoundException":
                    return
                raise
            time.sleep(15)
        raise AssertionError(f"cluster {cluster_arn} still exists {timeout_s}s after DeleteCluster")

    ctx.on_cleanup(_cleanup)
    state = _wait_cluster_state(ctx, cluster_arn, {"ACTIVE", "FAILED"}, timeout_s=timeout_s)
    if state != "ACTIVE":
        raise AssertionError(f"cluster entered {state} instead of ACTIVE")
    return cluster_arn


def _error_code(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected DeleteChannel to be rejected, but it SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
