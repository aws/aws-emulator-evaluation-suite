"""compatible-kafka-versions-nonexistent-cluster-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "compatible-kafka-versions-nonexistent-cluster-not-found"
GROUP = 'kafka-versions'
SERVICES = ['kafka']

def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises.

    Raises if the call succeeds, so an emulator that accepts what AWS refuses fails
    loudly instead of reading as a code mismatch."""
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {resp!r}")


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
    """GetCompatibleKafkaVersions returns the account-wide catalog without a ClusterArn and fails with
    NotFoundException and its exact message for a cluster that does not exist."""
    msk = ctx.client("kafka")

    catalog = msk.get_compatible_kafka_versions().get("CompatibleKafkaVersions")
    assert catalog, f"account-wide GetCompatibleKafkaVersions returned nothing: {catalog!r}"

    code, message = _err(
        lambda: msk.get_compatible_kafka_versions(ClusterArn=_bogus_cluster_arn(ctx))
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "The requested resource doesn\u2019t exist.", message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
