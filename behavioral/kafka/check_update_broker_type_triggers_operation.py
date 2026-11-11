"""update-broker-type-triggers-operation."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-broker-type-triggers-operation"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")


# MSK's message for a cluster ARN that resolves to nothing (U+2019 apostrophe).
_NOT_FOUND = ("NotFoundException", "The requested resource doesn\u2019t exist.")


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateBrokerType for a cluster that does not exist fails with NotFoundException, and DescribeCluster
    and ListClusterOperations then report not-found too, so neither the cluster nor an operation was
    created."""
    msk = ctx.client("kafka")
    ghost = _bogus_cluster_arn(ctx)

    err = _err(
        lambda: msk.update_broker_type(
            ClusterArn=ghost, CurrentVersion="1", TargetInstanceType="kafka.m5.large"
        )
    )
    assert err == _NOT_FOUND, f"UpdateBrokerType: expected {_NOT_FOUND!r}, got {err!r}"

    listed = _err(lambda: msk.list_cluster_operations(ClusterArn=ghost))
    assert listed == _NOT_FOUND, f"ListClusterOperations: expected {_NOT_FOUND!r}, got {listed!r}"

    described = _err(lambda: msk.describe_cluster(ClusterArn=ghost))
    assert described == _NOT_FOUND, f"DescribeCluster: expected {_NOT_FOUND!r}, got {described!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
