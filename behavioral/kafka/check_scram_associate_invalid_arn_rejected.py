"""scram-associate-invalid-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scram-associate-invalid-arn-rejected"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    SUCCESS raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal
    available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
    """BatchAssociateScramSecret fails a non-Secrets-Manager SecretArn with BadRequestException "The
    provided secret ARN is invalid.", while a well-formed secret on a missing cluster fails with
    NotFoundException."""
    msk = ctx.client("kafka")
    ghost_cluster = _bogus_cluster_arn(ctx)

    # Positive control: the client/credentials/service are generally healthy.
    msk.list_kafka_versions()

    malformed = _err(
        lambda: msk.batch_associate_scram_secret(
            ClusterArn=ghost_cluster, SecretArnList=["not-a-secrets-manager-arn"]
        )
    )
    assert malformed == ("BadRequestException", "The provided secret ARN is invalid."), (
        f"malformed secret ARN must be BadRequestException, got {malformed!r}"
    )

    wellformed_secret = (
        f"arn:aws:secretsmanager:{ctx.region}:{_account_id(ctx)}:secret:AmazonMSK_"
        f"{ctx.unique_name('sim2real-behav-')}-AbCdEf"
    )
    missing_cluster = _err(
        lambda: msk.batch_associate_scram_secret(
            ClusterArn=ghost_cluster, SecretArnList=[wellformed_secret]
        )
    )
    assert missing_cluster == ("NotFoundException", "The requested resource doesn\u2019t exist."), (
        f"well-formed secret against a nonexistent cluster must be NotFoundException, "
        f"got {missing_cluster!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
