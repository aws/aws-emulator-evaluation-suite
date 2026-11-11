"""update-storage-server-enforced."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-storage-server-enforced"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

_NOT_FOUND = ("NotFoundException", "The requested resource doesn\u2019t exist.")

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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateStorage for a cluster that does not exist, both for a volume change and for TIERED mode, fails
    with NotFoundException, and DescribeCluster then reports not-found too."""
    msk = ctx.client("kafka")
    ghost = _bogus_cluster_arn(ctx)

    err = _err(
        lambda: msk.update_storage(ClusterArn=ghost, CurrentVersion="1", VolumeSizeGB=20)
    )
    assert err == _NOT_FOUND, f"VolumeSizeGB form: expected {_NOT_FOUND!r}, got {err!r}"

    tiered = _err(
        lambda: msk.update_storage(ClusterArn=ghost, CurrentVersion="1", StorageMode="TIERED")
    )
    assert tiered == _NOT_FOUND, f"StorageMode form: expected {_NOT_FOUND!r}, got {tiered!r}"

    described = _err(lambda: msk.describe_cluster(ClusterArn=ghost))
    assert described == _NOT_FOUND, f"DescribeCluster: expected {_NOT_FOUND!r}, got {described!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
