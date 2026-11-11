"""get-key-last-usage-invalid-arn-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-key-last-usage-invalid-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetKeyLastUsage with a malformed ARN in the caller's account returns NotFoundException
    ("Invalid arn ..."), not ValidationException; KeyId has no pattern constraint, only a length.
    """
    kms = ctx.client("kms")

    # The ARN must name the caller's account: another account is refused earlier with
    # AccessDeniedException. The extra empty colon field is the malformation.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    malformed_arn = f"arn:aws:kms::{ctx.region}:{account_id}:key/00000000-0000-0000-0000-000000000000"

    code, message = _error(lambda: kms.get_key_last_usage(KeyId=malformed_arn))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == f"Invalid arn {malformed_arn}", f"unexpected message: {message!r}"

    # positive control: a syntactically valid ARN naming a real key succeeds
    key_id = _create_symmetric_key(ctx)
    key_arn = kms.describe_key(KeyId=key_id)["KeyMetadata"]["Arn"]
    resp = kms.get_key_last_usage(KeyId=key_arn)
    assert "KeyCreationDate" in resp, f"expected KeyCreationDate in response, got {resp!r}"


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_symmetric_key(ctx):
    kms = ctx.client("kms")
    key = kms.create_key(Description=ctx.unique_name("sim2real-behav-"))["KeyMetadata"]
    key_id = key["KeyId"]
    ctx.on_cleanup(lambda: _safe_schedule_delete(kms, key_id))
    return key_id


def _safe_schedule_delete(client, key_id):
    try:
        client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
