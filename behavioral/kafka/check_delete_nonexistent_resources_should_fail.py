"""delete-nonexistent-resources-should-fail."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-nonexistent-resources-should-fail"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

# Real MSK's refusal for a never-issued ARN. The message carries a
# typographic apostrophe (U+2019), not an ASCII one.
_MISSING = ("NotFoundException", "The requested resource doesn\u2019t exist.")
_MISSING_REPLICATOR = (
    "NotFoundException",
    "Invalid parameter replicatorArn: The requested resource doesn\u2019t exist.",
)
_MISSING_CONFIGURATION = ("BadRequestException", "Configuration ARN does not exist.")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Every MSK Delete* (cluster, topic, configuration, channel, replicator, VPC connection,
    cluster policy) on a never-issued ARN errors, and so does a second delete of a configuration
    once it is gone: real MSK does not treat delete as idempotent for unknown ids.
    """
    kafka = ctx.client("kafka")
    account_id = _account_id(ctx)
    ghost_cluster = _fake_cluster_arn(ctx, account_id)
    ghost_conn = _fake_vpc_connection_arn(ctx, account_id)
    delete_vpc_member = _arn_member(kafka, "DeleteVpcConnection", "Arn", "VpcConnectionArn")

    cases: list[tuple[str, str, object, tuple]] = [
        (
            "DeleteCluster",
            "DeleteCluster",
            lambda: kafka.delete_cluster(ClusterArn=ghost_cluster),
            _MISSING,
        ),
        (
            "DeleteTopic",
            "DeleteTopic",
            lambda: kafka.delete_topic(
                ClusterArn=ghost_cluster, TopicName=ctx.unique_name("sim2real-behav-ghost-topic-")
            ),
            _MISSING,
        ),
        (
            "DeleteConfiguration",
            "DeleteConfiguration",
            lambda: kafka.delete_configuration(Arn=_fake_configuration_arn(ctx, account_id)),
            _MISSING_CONFIGURATION,
        ),
        (
            "DeleteChannel",
            "DeleteChannel",
            lambda: kafka.delete_channel(
                ChannelArn=_fake_channel_arn(ctx, account_id), ClusterArn=ghost_cluster
            ),
            _MISSING,
        ),
        (
            "DeleteReplicator",
            "DeleteReplicator",
            lambda: kafka.delete_replicator(ReplicatorArn=_fake_replicator_arn(ctx, account_id)),
            _MISSING_REPLICATOR,
        ),
        (
            "DeleteVpcConnection",
            "DeleteVpcConnection",
            lambda: kafka.delete_vpc_connection(**{delete_vpc_member: ghost_conn}),
            _MISSING,
        ),
        (
            "DeleteClusterPolicy",
            "DeleteClusterPolicy",
            lambda: kafka.delete_cluster_policy(ClusterArn=ghost_cluster),
            _MISSING,
        ),
    ]

    observed: dict[str, tuple] = {}
    unsupported: list[str] = []
    for label, op_name, call, expected in cases:
        if not _has_operation(kafka, op_name):
            # The pinned botocore model predates this MSK operation; there is
            # nothing to probe rather than something to assert.
            unsupported.append(op_name)
            continue
        observed[label] = _api_error(label, call)
        assert observed[label] == expected, f"{label}: expected {expected!r}, got {observed[label]!r}"

    assert observed, f"no Delete* operation could be probed (unsupported: {unsupported})"
    assert not unsupported, f"MSK operations missing from the SDK model: {unsupported}"

    # --- already-deleted (not merely never-existed) -------------------------
    # A configuration is the one deletable MSK resource that can be created and
    # destroyed in seconds, so it carries the strict half of this contract.
    #
    # Empirically, DeleteConfiguration is
    # IDEMPOTENT while the configuration is still draining through DELETING --
    # a second delete issued in that window answers 200, same as the first.
    # Only once DescribeConfiguration itself stops succeeding (empirically
    # BadRequestException, not NotFoundException, for this resource type) has
    # the configuration actually gone -- and only past that point does a
    # duplicate delete stop being idempotent. Testing the "already-deleted"
    # contract therefore means waiting for the independent read to fail
    # first, then asserting the second delete fails with the same refusal.
    config_arn, _config_name = _create_configuration(ctx)
    first_delete = kafka.delete_configuration(Arn=config_arn)
    assert first_delete["Arn"] == config_arn, first_delete
    assert first_delete["State"] == "DELETING", (
        f"deleting a configuration we just created should transition it to "
        f"DELETING, got {first_delete['State']!r}"
    )

    # Independent read (DescribeConfiguration, not DeleteConfiguration) proving
    # the delete actually took effect: keep reading until the read itself is
    # rejected, which is this resource's real not-found signal.
    describe_gone = _wait_configuration_gone(kafka, config_arn)
    assert describe_gone == _MISSING_CONFIGURATION, (
        f"DescribeConfiguration on an already-deleted configuration: expected "
        f"{_MISSING_CONFIGURATION!r}, got {describe_gone!r}"
    )

    repeat = _api_error("re-delete", lambda: kafka.delete_configuration(Arn=config_arn))
    assert repeat == _MISSING_CONFIGURATION, (
        f"re-deleting a configuration DescribeConfiguration already reports as gone: "
        f"expected {_MISSING_CONFIGURATION!r}, got {repeat!r}"
    )



DEFAULT_KAFKA_VERSION = "3.9.x"


def _api_error(label: str, fn) -> tuple[str, str]:
    """Call fn(); return the API error (Code, Message) it raises.

    Success raises AssertionError; a ParamValidationError (a malformed request) propagates.
    """
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"{label} SUCCEEDED on an invalid target; real AWS rejects this")


def _has_operation(kafka, op_name: str) -> bool:
    """True when the bundled botocore model knows the MSK operation."""
    try:
        kafka.meta.service_model.operation_model(op_name)
    except Exception:  # noqa: BLE001 — model introspection is best-effort
        return False
    return True


def _arn_member(kafka, op_name: str, *candidates: str) -> str:
    """Pick the first candidate member name the operation accepts; MSK spells it either ``Arn``
    or ``<Resource>Arn``."""
    try:
        shape = kafka.meta.service_model.operation_model(op_name).input_shape
        members = set(shape.members) if shape is not None else set()
    except Exception:  # noqa: BLE001
        members = set()
    for candidate in candidates:
        if candidate in members:
            return candidate
    return candidates[0]


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


# --- syntactically well-formed but NEVER-ISSUED MSK ARNs ---

def _fake_cluster_arn(ctx, account_id: str) -> str:
    name = ctx.unique_name("sim2real-behav-ghost-cluster-")
    return f"arn:aws:kafka:{ctx.region}:{account_id}:cluster/{name}/{uuid.uuid4()}-2"


def _fake_configuration_arn(ctx, account_id: str) -> str:
    name = ctx.unique_name("sim2real-behav-ghost-config-")
    return f"arn:aws:kafka:{ctx.region}:{account_id}:configuration/{name}/{uuid.uuid4()}-1"


def _fake_replicator_arn(ctx, account_id: str) -> str:
    name = ctx.unique_name("sim2real-behav-ghost-repl-")
    return f"arn:aws:kafka:{ctx.region}:{account_id}:replicator/{name}/{uuid.uuid4()}-2"


def _fake_vpc_connection_arn(ctx, account_id: str) -> str:
    cluster_name = ctx.unique_name("sim2real-behav-ghost-cluster-")
    return (
        f"arn:aws:kafka:{ctx.region}:{account_id}:"
        f"vpc-connection/{account_id}/{cluster_name}/{uuid.uuid4()}-2"
    )


def _fake_channel_arn(ctx, account_id: str) -> str:
    cluster_name = ctx.unique_name("sim2real-behav-ghost-cluster-")
    chan_name = ctx.unique_name("sim2real-behav-ghost-chan-")
    return (
        f"arn:aws:kafka:{ctx.region}:{account_id}:"
        f"channel/{cluster_name}/{uuid.uuid4()}-2/{chan_name}"
    )


def _supported_kafka_version(kafka) -> str:
    """An ACTIVE Kafka version the region offers, preferring the default; hard-coded versions get
    deprecated."""
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


def _create_configuration(ctx, server_properties: str = "auto.create.topics.enable=true"):
    """A configuration is the one deletable MSK resource whose whole lifecycle
    fits in seconds -- no cluster provisioning, so nothing billable."""
    kafka = ctx.client("kafka")
    name = ctx.unique_name("sim2real-behav-kfk-cfg-")
    arn = kafka.create_configuration(
        Name=name,
        ServerProperties=server_properties.encode("utf-8"),
        KafkaVersions=[_supported_kafka_version(kafka)],
    )["Arn"]
    # CreateConfiguration has no Tags member; TagResource is the only way to
    # mark this resource for a tag search.
    _swallow(lambda: kafka.tag_resource(ResourceArn=arn, Tags={"sim2real:managed": "true"}))
    ctx.on_cleanup(lambda: _delete_configuration(kafka, arn))
    return arn, name


def _wait_configuration_gone(kafka, arn: str, timeout_s: float = 120) -> tuple[str, str]:
    """Poll DescribeConfiguration until it fails and return the error (Code, Message); a failing
    read, not a non-ACTIVE state, is this resource's not-found signal. Raises on timeout."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            kafka.describe_configuration(Arn=arn)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        time.sleep(5)
    raise AssertionError(f"DescribeConfiguration still succeeds {timeout_s}s after deleting {arn}")


def _swallow(fn):
    try:
        fn()
    except Exception:  # noqa: BLE001 — the tag is only a search marker
        pass


def _delete_configuration(kafka, arn):
    try:
        kafka.delete_configuration(Arn=arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
