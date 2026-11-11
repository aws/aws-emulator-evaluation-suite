"""replicate-key-invalid-arn-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "replicate-key-invalid-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ReplicateKey with a malformed source key ARN fails with InvalidArnException and the exact message, while a
    well-formed ARN of a single-Region key fails with UnsupportedOperationException
    "<arn> is not a multi-region key."."""
    kms = ctx.client("kms")
    sts = ctx.client("sts")

    # A syntactically valid alias ARN (nonexistent alias, but our own real account) --
    # ReplicateKey only replicates multi-Region primary KMS keys, and an alias reference
    # does not name a key resource at all, so KMS rejects it as an invalid ARN before ever
    # attempting to resolve a primary key.
    account_id = sts.get_caller_identity()["Account"]
    malformed_arn = f"arn:aws:kms:{ctx.region}:{account_id}:alias/sim2real-nonexistent"
    # ReplicaRegion must simply differ from ctx.region for this call to be well-formed;
    # no assertion depends on which region it names.
    other_region = "us-east-1" if ctx.region != "us-east-1" else "us-west-2"

    code, message = _error(lambda: kms.replicate_key(KeyId=malformed_arn, ReplicaRegion=other_region))
    assert code == "InvalidArnException", code
    assert message == "Key Aliases are not supported for this operation.", message

    # positive control: a well-formed ARN of a real, single-Region key passes ARN
    # validation and instead fails because it is not a multi-Region primary key.
    key = kms.create_key(
        Description=ctx.unique_name("sim2real-kms-repl-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-behavioral"}],
    )
    key_id = key["KeyMetadata"]["KeyId"]
    key_arn = key["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    assert key["KeyMetadata"]["MultiRegion"] is False, (
        f"a freshly created key with no MultiRegion option was MultiRegion="
        f"{key['KeyMetadata']['MultiRegion']!r}; expected False"
    )

    control_code, control_message = _error(
        lambda: kms.replicate_key(KeyId=key_arn, ReplicaRegion=other_region)
    )
    assert control_code == "UnsupportedOperationException", control_code
    assert control_message == f"{key_arn} is not a multi-region key.", control_message


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an over-permissive target accepting a call real AWS rejects is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
