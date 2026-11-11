"""cluster-policy-sequential-overwrite-latest-wins."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-policy-sequential-overwrite-latest-wins"
GROUP = "concurrency"
SERVICES = ["kafka"]


def _error_code(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) of the ClientError it raises.

    Raises (rather than returning a falsy sentinel) if the call unexpectedly succeeds.
    """
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected a ClientError, call unexpectedly succeeded with {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Once a cluster policy exists, PutClusterPolicy without CurrentVersion fails with BadRequestException
    and leaves the policy and version unchanged; with the prior version the new document replaces the old
    one with a new version."""
    kafka_version = _pick_active_kafka_version(ctx)
    cluster_arn = _create_basic_cluster(ctx, kafka_version)

    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    kafka = ctx.client("kafka")
    principal = f"arn:aws:iam::{account_id}:root"

    policy_one = (
        '{"Version":"2012-10-17","Statement":[{"Sid":"AllowActionOne","Effect":"Allow",'
        f'"Principal":{{"AWS":"{principal}"}},"Action":"kafka:GetBootstrapBrokers",'
        f'"Resource":"{cluster_arn}"}}]}}'
    )
    policy_two = (
        '{"Version":"2012-10-17","Statement":[{"Sid":"AllowActionTwo","Effect":"Allow",'
        f'"Principal":{{"AWS":"{principal}"}},"Action":"kafka:DescribeCluster",'
        f'"Resource":"{cluster_arn}"}}]}}'
    )
    assert policy_one != policy_two, "test fixture bug: the two policies must differ"

    put_one = kafka.put_cluster_policy(ClusterArn=cluster_arn, Policy=policy_one)
    ctx.on_cleanup(lambda: kafka.delete_cluster_policy(ClusterArn=cluster_arn))
    version_one = put_one.get("CurrentVersion")
    assert version_one, f"PutClusterPolicy did not return a CurrentVersion: {put_one!r}"

    code, message = _error_code(
        lambda: kafka.put_cluster_policy(ClusterArn=cluster_arn, Policy=policy_two)
    )
    assert code == "BadRequestException", (
        f"expected a version-less PutClusterPolicy against an existing policy to be "
        f"rejected with BadRequestException, got {code!r}"
    )
    assert message == "Current cluster policy version needed for Update", (
        f"version-less PutClusterPolicy message: {message!r}"
    )

    unchanged = kafka.get_cluster_policy(ClusterArn=cluster_arn)
    assert unchanged["Policy"] == policy_one, (
        "a rejected version-less PutClusterPolicy must not have touched the stored policy, "
        f"got {unchanged['Policy']!r}"
    )
    assert unchanged["CurrentVersion"] == version_one, (
        "a rejected PutClusterPolicy must not have advanced the version"
    )

    put_two = kafka.put_cluster_policy(
        ClusterArn=cluster_arn, Policy=policy_two, CurrentVersion=version_one
    )
    version_two = put_two.get("CurrentVersion")
    assert version_two and version_two != version_one, (
        f"expected a fresh CurrentVersion after a versioned Put, got {version_two!r} "
        f"(was {version_one!r})"
    )

    resp = kafka.get_cluster_policy(ClusterArn=cluster_arn)
    assert resp["Policy"] == policy_two, "expected the second PutClusterPolicy to win outright"
    assert "AllowActionOne" not in resp["Policy"], (
        "the first policy's statement leaked into the stored policy -- not a clean overwrite"
    )
    assert "AllowActionTwo" in resp["Policy"], (
        f"expected the second policy's statement to be present, got {resp['Policy']!r}"
    )


def _default_client_subnets(ctx, count: int = 2) -> list[str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network available to place MSK broker subnets")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())[:count]
    if len(subnet_ids) < count:
        raise AssertionError(f"shared network has fewer than {count} usable availability zones")
    return subnet_ids


def _poll_cluster_state(
    ctx, cluster_arn: str, desired: set[str], timeout_s: float = 1800.0, interval_s: float = 20.0
) -> dict[str, Any]:
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]
        last = info["State"]
        if last in desired:
            return info
        if last == "FAILED":
            raise AssertionError(f"cluster entered FAILED state: {info.get('StateInfo')}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster did not reach {desired} within {timeout_s}s (last state={last})")


def _create_basic_cluster(ctx, kafka_version: str, **extra: Any) -> str:
    kafka = ctx.client("kafka")
    subnets = _default_client_subnets(ctx, 2)
    name = ctx.unique_name("sim2real-behav-")
    kwargs: dict[str, Any] = dict(
        ClusterName=name,
        KafkaVersion=kafka_version,
        NumberOfBrokerNodes=len(subnets),
        BrokerNodeGroupInfo={
            "InstanceType": "kafka.t3.small",
            "ClientSubnets": subnets,
            "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 100}},
        },
        Tags={"sim2real:managed": "true"},
    )
    kwargs.update(extra)
    resp = kafka.create_cluster(**kwargs)
    arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_when_settled(kafka, arn))
    _poll_cluster_state(ctx, arn, {"ACTIVE"})
    return arn


def _pick_active_kafka_version(ctx) -> str:
    # Standard brokers accept 3.9.x; they reject older versions and the Express-only 4.2.x.
    status = {v["Version"]: v.get("Status") for v in ctx.client("kafka").list_kafka_versions().get("KafkaVersions", [])}
    if status.get("3.9.x") != "ACTIVE":
        raise AssertionError(f"Kafka 3.9.x is not ACTIVE in ListKafkaVersions: {sorted(status)}")
    return "3.9.x"


def _delete_cluster_when_settled(msk, arn, timeout_s=2400.0, interval_s=30.0):
    """DeleteCluster refuses a cluster that is CREATING or UPDATING, so wait for ACTIVE or FAILED first."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            state = msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["State"]
            if state == "DELETING":
                return
            if state in ("ACTIVE", "FAILED"):
                msk.delete_cluster(ClusterArn=arn)
                return
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"cluster {arn} still {state} after {timeout_s:.0f}s; it cannot be deleted")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
