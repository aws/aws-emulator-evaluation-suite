"""get-session-token-credentials-invalid-after-expiration-boundary."""
from __future__ import annotations

from datetime import datetime, timezone

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-session-token-credentials-invalid-after-expiration-boundary"
GROUP = "visibility-timeout-ttl"
SERVICES = ["sts"]


@tags("axis:happy-path", "cap:c7", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSessionToken credentials call GetCallerIdentity immediately, Expiration is ~900 s out,
    and DurationSeconds=899 fails ValidationError with the exact minimum-900 message.
    """
    sts = ctx.client("sts")
    resp = sts.get_session_token(DurationSeconds=900)
    creds = resp["Credentials"]
    expiration = creds["Expiration"]
    session_sts = _client_with_creds(ctx, "sts", creds)

    session_sts.get_caller_identity()

    now = datetime.now(timezone.utc)
    observed_ttl = (expiration - now).total_seconds()
    assert abs(observed_ttl - 900) < 30, f"unexpected Expiration offset: {observed_ttl}s"

    # botocore validates min=900 locally; disable client-side validation so 899 reaches STS.
    unvalidated = ctx.client("sts", config=Config(parameter_validation=False))
    floor_code, floor_message = _refusal(
        lambda: unvalidated.get_session_token(DurationSeconds=899)
    )
    assert floor_code == "ValidationError", f"unexpected code: {floor_code}"
    expected_message = (
        "1 validation error detected: Value '899' at 'durationSeconds' failed to satisfy "
        "constraint: Member must have value greater than or equal to 900"
    )
    assert floor_message == expected_message, (
        f"expected the refusal message {expected_message!r}, got {floor_message!r}"
    )


def _client_with_creds(ctx, service: str, creds: dict):
    return ctx.client(service, creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })


def _refusal(fn):
    """The (code, message) of a refused call; raises when the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
