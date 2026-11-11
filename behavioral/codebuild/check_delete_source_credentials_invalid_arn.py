"""delete-source-credentials-invalid-arn."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _delete(cb, arn):
    try:
        cb.delete_source_credentials(arn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_expect_rejected(cb, arn):
    """DeleteSourceCredentials(arn); return (code, message). An unexpected SUCCESS raises, so
    acceptance of a malformed ARN is never reported as a code mismatch."""
    try:
        cb.delete_source_credentials(arn=arn)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected DeleteSourceCredentials(arn={arn!r}) to be rejected, but it succeeded"
    )


CHECK = "delete-source-credentials-invalid-arn"
GROUP = 'error-semantics'
SERVICES = ['codebuild']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:codebuild-source-credentials")
def run(ctx) -> None:
    """DeleteSourceCredentials with a malformed credential ARN is rejected with InvalidInputException
    and changes nothing, while the same call on a real imported credential succeeds.
    """
    cb = ctx.client("codebuild")

    imported = cb.import_source_credentials(
        token="ghp_test_token_sdk",
        serverType="GITHUB",
        authType="PERSONAL_ACCESS_TOKEN",
        shouldOverwrite=True,
    )
    real_arn = imported["arn"]
    ctx.on_cleanup(lambda: _delete(cb, real_arn))

    listed = {c.get("arn") for c in cb.list_source_credentials().get("sourceCredentialsInfos", [])}
    assert real_arn in listed, listed

    # Positive control: the same operation, a real ARN, succeeds.
    cb.delete_source_credentials(arn=real_arn)
    after_real_delete = {
        c.get("arn") for c in cb.list_source_credentials().get("sourceCredentialsInfos", [])
    }
    assert real_arn not in after_real_delete, (
        f"the positive-control delete did not remove {real_arn!r}: {after_real_delete!r}"
    )

    code, message = _delete_expect_rejected(
        cb, "arn:aws:codebuild:region:account:token/does_not_exist"
    )
    assert code == "InvalidInputException", code
    assert message == "Invalid ARN: region region is invalid", message

    after_reject = {
        c.get("arn") for c in cb.list_source_credentials().get("sourceCredentialsInfos", [])
    }
    assert after_reject == after_real_delete, (
        f"the rejected delete on a malformed ARN changed the credential listing: "
        f"{after_real_delete!r} -> {after_reject!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
