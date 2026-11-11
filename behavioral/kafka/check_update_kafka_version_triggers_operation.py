"""update-kafka-version-triggers-operation."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-kafka-version-triggers-operation"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

_NOT_FOUND = ("NotFoundException", "The requested resource doesn\u2019t exist.")

_DEFAULT_KAFKA_VERSION = "3.8.x"


def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) of the ClientError it raises.

    An unexpected SUCCESS raises with the actual result, because an emulator ACCEPTING a call real
    AWS refuses is the strongest signal available.
    """
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _account_id(ctx):
    if not hasattr(ctx, "_kafka_account_id"):
        ctx._kafka_account_id = ctx.client("sts").get_caller_identity()["Account"]
    return ctx._kafka_account_id


def _bogus_cluster_arn(ctx):
    """A well-formed MSK cluster ARN, in this account, that cannot exist."""
    return (
        f"arn:aws:kafka:{ctx.region}:{_account_id(ctx)}:cluster/"
        f"{ctx.unique_name('sim2real-behav-nonexistent-')}/"
        "00000000-0000-0000-0000-000000000000-1"
    )


def _bogus_operation_arn(cluster_arn):
    """A well-formed cluster-operation ARN under cluster_arn that was never issued."""
    base = cluster_arn.replace(":cluster/", ":cluster-operation/", 1)
    return f"{base}/00000000-0000-0000-0000-000000000000"


@tags("axis:rejection", "cap:c1", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A nonexistent cluster's upgrade and operation lookups all fail NotFoundException.

    UpdateClusterKafkaVersion to a compatible target version, ListClusterOperations and
    DescribeClusterOperation each return the same exact (code, message).
    """
    msk = ctx.client("kafka")
    pairs = msk.get_compatible_kafka_versions()["CompatibleKafkaVersions"]
    targets = [
        t
        for p in pairs
        if p["SourceVersion"] == _DEFAULT_KAFKA_VERSION
        for t in p.get("TargetVersions", [])
        if t != _DEFAULT_KAFKA_VERSION
    ]
    if not targets:
        # Fall back to any advertised upgrade path if the default source is absent.
        targets = [
            t for p in pairs for t in p.get("TargetVersions", []) if t != p["SourceVersion"]
        ]
    if not targets:
        raise AssertionError("no compatible Kafka upgrade target advertised by GetCompatibleKafkaVersions")
    numeric = [t for t in targets if all(part.isdigit() for part in t.split("."))]
    target = (numeric or targets)[0]

    ghost = _bogus_cluster_arn(ctx)
    err = _err(
        lambda: msk.update_cluster_kafka_version(
            ClusterArn=ghost, CurrentVersion="1", TargetKafkaVersion=target
        )
    )
    assert err == _NOT_FOUND, f"expected {_NOT_FOUND!r}, got {err!r}"

    listed = _err(lambda: msk.list_cluster_operations(ClusterArn=ghost))
    assert listed == _NOT_FOUND, f"ListClusterOperations: expected {_NOT_FOUND!r}, got {listed!r}"

    described = _err(
        lambda: msk.describe_cluster_operation(ClusterOperationArn=_bogus_operation_arn(ghost))
    )
    assert described == _NOT_FOUND, (
        f"DescribeClusterOperation: expected {_NOT_FOUND!r}, got {described!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
