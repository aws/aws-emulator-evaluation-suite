"""ops-metadata-get-nonexistent-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "ops-metadata-get-nonexistent-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm"]

_NOT_FOUND_MESSAGE = (
    "OpsMetadata object not found. Verify the Amazon Resource Name (ARN) and try again."
)
_NOT_OWNER_MESSAGE = (
    "Invalid OpsMetadataArn. Requester is not the owner of the resource. Verify the "
    "Amazon Resource Name (ARN) and try again."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetOpsMetadata on a well-formed unregistered OpsMetadataArn fails with
    OpsMetadataNotFoundException and the exact message, while an ARN naming another account fails
    with OpsMetadataInvalidArgumentException and the not-owner message."""
    ssm = ctx.client("ssm")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # Well-formed ARN (real account, plausible resource path) that was never registered.
    fake_arn = (
        f"arn:aws:ssm:{ctx.region}:{account_id}:opsmetadata/"
        f"{ctx.unique_name('sim2real-opsmeta-nope-')}"
    )
    code, message = _error(lambda: ssm.get_ops_metadata(OpsMetadataArn=fake_arn))
    assert code == "OpsMetadataNotFoundException", f"got {code!r}"
    assert message == _NOT_FOUND_MESSAGE, message

    # A malformed ARN (account that isn't ours) is a distinct failure mode --
    # it must NOT be reported as the same NotFound error.
    malformed_arn = (
        f"arn:aws:ssm:{ctx.region}:111122223333:opsmetadata/"
        f"{ctx.unique_name('sim2real-opsmeta-nope-')}"
    )
    malformed_code, malformed_message = _error(
        lambda: ssm.get_ops_metadata(OpsMetadataArn=malformed_arn)
    )
    assert malformed_code == "OpsMetadataInvalidArgumentException", (
        f"malformed ARN should be refused as an invalid argument, not NotFound, got "
        f"{malformed_code!r}"
    )
    assert malformed_message == _NOT_OWNER_MESSAGE, malformed_message


def _error(fn):
    """Return the (code, message) of the ClientError fn raises; raise if fn succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"the call was expected to be refused but it succeeded: {result!r}")


def _delete_ops_metadata_if_exists(ssm, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ssm.delete_ops_metadata(OpsMetadataArn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "OpsMetadataNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
