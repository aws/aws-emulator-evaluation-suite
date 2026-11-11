"""batch-disassociate-scram-secret-malformed-arn-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-disassociate-scram-secret-malformed-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["kafka"]

_NOT_FOUND_MESSAGE = "The requested resource doesn\u2019t exist."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchDisassociateScramSecret rejects a non-ARN secret string with the same NotFoundException and
    message it returns for a well-formed ARN of a secret that does not exist."""
    kafka = ctx.client("kafka")
    fake_cluster_arn = _fake_cluster_arn(ctx)

    # Positive control: the client/credentials/service are generally healthy.
    kafka.list_kafka_versions()

    # Not-an-ARN-at-all secret string: rejected, not silently accepted/ignored.
    malformed_code, malformed_message = _error_code(
        lambda: kafka.batch_disassociate_scram_secret(
            ClusterArn=fake_cluster_arn, SecretArnList=["not-an-arn-at-all"]
        )
    )
    assert malformed_code == "NotFoundException", repr(malformed_code)
    assert malformed_message == _NOT_FOUND_MESSAGE, repr(malformed_message)

    # Well-formed-but-nonexistent secret ARN on the same nonexistent cluster ARN: rejected
    # with the identical error code, confirming the API funnels both failure shapes through
    # one consistent "not found" contract rather than distinguishing malformed vs. missing.
    well_formed_but_missing_secret_arn = (
        f"arn:aws:secretsmanager:{ctx.region}:123456789012:secret:AmazonMSK_does-not-exist-x1y2z3"
    )
    lookup_code, lookup_message = _error_code(
        lambda: kafka.batch_disassociate_scram_secret(
            ClusterArn=fake_cluster_arn, SecretArnList=[well_formed_but_missing_secret_arn]
        )
    )
    assert lookup_code == "NotFoundException", repr(lookup_code)
    assert lookup_message == _NOT_FOUND_MESSAGE, repr(lookup_message)
    assert (lookup_code, lookup_message) == (malformed_code, malformed_message)


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _fake_cluster_arn(ctx):
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-nonexistent-")
    return (
        f"arn:aws:kafka:{ctx.region}:{account_id}:cluster/{name}/"
        "00000000-0000-0000-0000-000000000000-1"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
