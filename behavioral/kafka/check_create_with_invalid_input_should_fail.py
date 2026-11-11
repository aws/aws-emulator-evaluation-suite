"""create-with-invalid-input-should-fail."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError, ParamValidationError

from behavioral_harness import tags

CHECK = "create-with-invalid-input-should-fail"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

# The signal is rejection-vs-silent-success, so a 200 is the only failure.
MISSING_RESOURCE_CODES = frozenset(
    {
        "AccessDeniedException",
        "BadRequestException",
        "ForbiddenException",
        "NotFoundException",
        "UnauthorizedException",
        "ValidationException",
    }
)

# Rejections acceptable for a mutation/creation carrying invalid input or aiming
# at a resource that does not exist.
INVALID_REQUEST_CODES = MISSING_RESOURCE_CODES | frozenset({"ConflictException"})

# ctx.unique_name's prefix, needed to recognise THIS check's own would-be
# clusters when asserting the rejected creates left nothing behind.
_BAD_CLUSTER_PREFIX = "sim2real-behav-bad-cluster"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Each Create* call with input MSK documents as invalid (missing subnets, neither Provisioned nor
    Serverless, an illegal configuration name, a nonexistent parent cluster) fails with a client error, and
    no cluster is created."""
    kafka = ctx.client("kafka")
    account_id = _account_id(ctx)
    ghost_cluster = _fake_cluster_arn(ctx, account_id)
    dead_subnets = ["subnet-00000000000000000", "subnet-11111111111111111"]

    # Positive control: a legitimately-named CreateConfiguration must succeed on
    # this account/credentials, so the illegal-name rejection below is known to be
    # about the name and not a blanket denial that would rubber-stamp every case.
    good_arn = kafka.create_configuration(
        Name=ctx.unique_name("sim2real-behav-good-config-"),
        ServerProperties=b"auto.create.topics.enable=true\n",
    )["Arn"]
    ctx.on_cleanup(lambda: kafka.delete_configuration(Arn=good_arn))

    cases: list[tuple[str, str, object]] = [
        (
            "CreateCluster(dead subnets)",
            "CreateCluster",
            lambda: kafka.create_cluster(
                ClusterName=ctx.unique_name(f"{_BAD_CLUSTER_PREFIX}-"),
                KafkaVersion=_supported_kafka_version(kafka),
                NumberOfBrokerNodes=2,
                BrokerNodeGroupInfo={
                    "InstanceType": "kafka.m5.large",
                    "ClientSubnets": dead_subnets,
                    "SecurityGroups": ["sg-00000000000000000"],
                    "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 1}},
                },
            ),
        ),
        (
            "CreateClusterV2(neither Provisioned nor Serverless)",
            "CreateClusterV2",
            lambda: kafka.create_cluster_v2(
                ClusterName=ctx.unique_name(f"{_BAD_CLUSTER_PREFIX}-v2-")
            ),
        ),
        (
            "CreateConfiguration(illegal name)",
            "CreateConfiguration",
            lambda: kafka.create_configuration(
                Name="sim2real behav illegal name!",
                ServerProperties=b"auto.create.topics.enable=true\n",
            ),
        ),
        (
            "CreateTopic(nonexistent cluster)",
            "CreateTopic",
            lambda: kafka.create_topic(
                ClusterArn=ghost_cluster,
                TopicName=ctx.unique_name("sim2real-behav-ghost-topic-"),
                PartitionCount=1,
                ReplicationFactor=1,
            ),
        ),
        (
            "CreateVpcConnection(nonexistent target cluster)",
            "CreateVpcConnection",
            lambda: kafka.create_vpc_connection(
                TargetClusterArn=ghost_cluster,
                Authentication="IAM",
                VpcId="vpc-00000000000000000",
                ClientSubnets=dead_subnets,
                SecurityGroups=["sg-00000000000000000"],
            ),
        ),
        (
            "CreateReplicator(nonexistent kafka clusters)",
            "CreateReplicator",
            lambda: kafka.create_replicator(
                ReplicatorName=ctx.unique_name("sim2real-behav-ghost-repl-"),
                ServiceExecutionRoleArn=(
                    f"arn:aws:iam::{account_id}:role/"
                    f"{ctx.unique_name('sim2real-behav-ghost-role-')}"
                ),
                KafkaClusters=[
                    {
                        "AmazonMskCluster": {"MskClusterArn": ghost_cluster},
                        "VpcConfig": {
                            "SubnetIds": dead_subnets,
                            "SecurityGroupIds": ["sg-00000000000000000"],
                        },
                    },
                    {
                        "AmazonMskCluster": {
                            "MskClusterArn": _fake_cluster_arn(ctx, account_id)
                        },
                        "VpcConfig": {
                            "SubnetIds": dead_subnets,
                            "SecurityGroupIds": ["sg-00000000000000000"],
                        },
                    },
                ],
                ReplicationInfoList=[
                    {
                        "SourceKafkaClusterArn": ghost_cluster,
                        "TargetKafkaClusterArn": _fake_cluster_arn(ctx, account_id),
                        "TargetCompressionType": "NONE",
                        "TopicReplication": {"TopicsToReplicate": ["*"]},
                        "ConsumerGroupReplication": {
                            "ConsumerGroupsToReplicate": ["*"]
                        },
                    }
                ],
            ),
        ),
    ]

    observed: dict[str, str] = {}
    unsupported: list[str] = []
    for label, op_name, call in cases:
        if not _has_operation(kafka, op_name):
            unsupported.append(op_name)
            continue
        code = _api_error(call)
        _assert_rejected(label, code, INVALID_REQUEST_CODES)
        observed[label] = code

    assert not unsupported, f"MSK operations missing from the SDK model: {unsupported}"
    assert len(observed) == len(cases)

    # No phantom cluster may have been created by the rejected CreateCluster*.
    names = set()
    for page in kafka.get_paginator("list_clusters_v2").paginate():
        for cluster in page.get("ClusterInfoList", []):
            names.add(cluster.get("ClusterName", ""))
    leaked = {n for n in names if n.startswith(_BAD_CLUSTER_PREFIX)}
    assert not leaked, f"rejected CreateCluster* still produced clusters: {leaked}"


DEFAULT_KAFKA_VERSION = "3.9.x"


def _assert_rejected(op_name: str, code: str | None, allowed: frozenset) -> None:
    """Shared assertion for every overly-permissive probe."""
    assert code is not None, (
        f"{op_name} SUCCEEDED on an invalid target — overly permissive; "
        f"real AWS rejects this"
    )
    assert code != "ParamValidationError", (
        f"{op_name} request was malformed client-side (botocore ParamValidationError) "
        f"— this is a bug in the check, not a service behaviour"
    )
    assert code in allowed, f"{op_name}: expected one of {sorted(allowed)}, got {code}"


def _api_error(fn) -> str | None:
    """Call fn(); return the API error code, or None if it SUCCEEDED.

    ParamValidationError is surfaced as its own pseudo-code so the check can tell
    "the service rejected this" apart from "we built a malformed request
    client-side" (the latter is a bug in the check, not a finding).
    """
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    except ParamValidationError:
        return "ParamValidationError"
    return None


def _has_operation(kafka, op_name: str) -> bool:
    """True when the bundled botocore model knows the MSK operation."""
    try:
        kafka.meta.service_model.operation_model(op_name)
    except Exception:  # noqa: BLE001 — model introspection is best-effort
        return False
    return True


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _fake_cluster_arn(ctx, account_id: str) -> str:
    """A syntactically well-formed but NEVER-ISSUED cluster ARN."""
    name = ctx.unique_name("sim2real-behav-ghost-cluster-")
    return f"arn:aws:kafka:{ctx.region}:{account_id}:cluster/{name}/{uuid.uuid4()}-2"


def _supported_kafka_version(kafka) -> str:
    """An ACTIVE Kafka version this account/region actually offers. Hard-coding a
    version rots (2.x versions get deprecated), so ask the service and prefer the
    default when it is still available."""
    try:
        versions = kafka.list_kafka_versions().get("KafkaVersions", [])
    except ClientError:
        versions = []
    active = [v["Version"] for v in versions if v.get("Status") == "ACTIVE" and v.get("Version")]
    if DEFAULT_KAFKA_VERSION in active:
        return DEFAULT_KAFKA_VERSION
    if active:
        # prefer a plain 3.x version (no ".x" express-only aliases)
        plain = [v for v in active if v[0] == "3" and not v.endswith(".x")]
        return sorted(plain or active)[-1]
    return DEFAULT_KAFKA_VERSION


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
