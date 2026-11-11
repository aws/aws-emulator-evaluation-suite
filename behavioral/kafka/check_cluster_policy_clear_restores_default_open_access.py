"""cluster-policy-clear-restores-default-open-access."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cluster-policy-clear-restores-default-open-access"
GROUP = "state-machine"
SERVICES = ["kafka"]

_CLUSTER_WAIT_TIMEOUT_S = 1800
_CLUSTER_POLL_INTERVAL_S = 30
_NOT_FOUND = ("NotFoundException", "The requested resource doesn\u2019t exist.")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeleteClusterPolicy, GetClusterPolicy reports no policy and a fresh PutClusterPolicy
    works cleanly -- proving there is no leftover cached policy version blocking state."""
    cluster_arn = _create_provisioned_cluster(ctx)
    kafka = ctx.client("kafka")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    def _policy_text(sid):
        return json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": sid,
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                        "Action": "kafka:DescribeCluster",
                        "Resource": cluster_arn,
                    }
                ],
            }
        )

    first_policy = _policy_text("FirstPolicy")
    kafka.put_cluster_policy(ClusterArn=cluster_arn, Policy=first_policy)
    got = kafka.get_cluster_policy(ClusterArn=cluster_arn)
    # GetClusterPolicy re-serializes the stored document (real AWS drops the whitespace
    # json.dumps put in), so the round-trip is compared structurally, not byte-for-byte.
    got_doc = json.loads(got["Policy"])
    assert got_doc == json.loads(first_policy), f"expected the just-put policy back verbatim, got {got_doc!r}"

    kafka.delete_cluster_policy(ClusterArn=cluster_arn)

    refused = _error_code(lambda: kafka.get_cluster_policy(ClusterArn=cluster_arn))
    assert refused == _NOT_FOUND, f"expected NotFoundException after delete, got {refused}"

    # Positive control: the cluster is not left in a broken/half-deleted state -- a fresh policy
    # can be attached (without needing any stale CurrentVersion) and read back correctly.
    second_policy = _policy_text("SecondPolicy")
    kafka.put_cluster_policy(ClusterArn=cluster_arn, Policy=second_policy)
    got2 = kafka.get_cluster_policy(ClusterArn=cluster_arn)
    got2_doc = json.loads(got2["Policy"])
    assert got2_doc == json.loads(second_policy), f"expected the second policy back verbatim, got {got2_doc!r}"
    assert got2_doc != got_doc, "expected the second policy to differ from the deleted first policy"


# ===== helpers =====
def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it succeeded with {result!r}")


def _default_vpc_subnets_and_sg(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to provision an MSK broker cluster")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network lacks subnets in at least 2 AZs required to place MSK broker nodes")
    subnet_ids = list(by_az.values())[:2]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"]
    return vpc_id, subnet_ids, sg_id


def _active_kafka_versions(ctx, pick="latest"):
    kafka = ctx.client("kafka")
    versions = kafka.list_kafka_versions().get("KafkaVersions", [])
    active = sorted(v["Version"] for v in versions if v.get("Status") == "ACTIVE")
    if not active:
        raise AssertionError("no ACTIVE Kafka version reported by ListKafkaVersions")
    return active if pick == "oldest" else list(reversed(active))


def _wait_for_cluster_state(
    ctx, arn, target_state, timeout_s=_CLUSTER_WAIT_TIMEOUT_S, interval_s=_CLUSTER_POLL_INTERVAL_S
):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster(ClusterArn=arn)["ClusterInfo"]
        last = info["State"]
        if last == target_state:
            return info
        if last == "FAILED":
            raise AssertionError(f"cluster {arn} entered FAILED state while waiting for {target_state}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {arn} did not reach {target_state} within {timeout_s}s (last observed: {last})")


def _delete_cluster_and_wait(ctx, arn, timeout_s=_CLUSTER_WAIT_TIMEOUT_S):
    kafka = ctx.client("kafka")
    try:
        kafka.delete_cluster(ClusterArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            kafka.describe_cluster(ClusterArn=arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"cluster {arn} was not deleted within {timeout_s}s")


def _create_provisioned_cluster(
    ctx, *, client_authentication=None, connectivity_info=None, kafka_version=None, version_pick="latest"
):
    kafka = ctx.client("kafka")
    _vpc_id, subnet_ids, sg_id = _default_vpc_subnets_and_sg(ctx)
    candidates = [kafka_version] if kafka_version else _active_kafka_versions(ctx, pick=version_pick)
    broker_node_group_info = {
        "InstanceType": "kafka.m5.large",
        "ClientSubnets": subnet_ids,
        "SecurityGroups": [sg_id],
    }
    if connectivity_info is not None:
        broker_node_group_info["ConnectivityInfo"] = connectivity_info
    provisioned_base = {
        "BrokerNodeGroupInfo": broker_node_group_info,
        "NumberOfBrokerNodes": len(subnet_ids),
    }
    if client_authentication is not None:
        provisioned_base["ClientAuthentication"] = client_authentication
    name = ctx.unique_name("sim2real-msk-")

    # ListKafkaVersions can report a version reserved for a different broker category (e.g.
    # Express-only) as ACTIVE; CreateClusterV2 then rejects it with a BadRequestException naming
    # the Standard-supporting alternatives. Probe candidates in order via the real call instead of
    # trusting the first ACTIVE entry.
    resp = None
    last_unsupported = None
    for version in candidates:
        try:
            resp = kafka.create_cluster_v2(
                ClusterName=name,
                Provisioned={**provisioned_base, "KafkaVersion": version},
                Tags={"sim2real:managed": "true"},
            )
            break
        except ClientError as e:
            err = e.response["Error"]
            if err["Code"] == "BadRequestException" and "not supported for Kafka version" in err.get("Message", ""):
                last_unsupported = e
                continue
            raise
    if resp is None:
        raise AssertionError(
            f"no ACTIVE Kafka version in {candidates} supports a Standard broker instance type: {last_unsupported}"
        )
    arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(ctx, arn))
    _wait_for_cluster_state(ctx, arn, "ACTIVE")
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
