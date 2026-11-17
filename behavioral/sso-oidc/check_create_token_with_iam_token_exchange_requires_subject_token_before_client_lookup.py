"""create-token-with-iam-token-exchange-requires-subject-token-before-client-lookup."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-token-with-iam-token-exchange-requires-subject-token-before-client-lookup"
GROUP = "error-semantics"
SERVICES = ["sso-oidc"]

_TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
_ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
_NO_SUBJECT_TOKEN = ("InvalidRequestException", "Subject Token is required")
_BAD_SUBJECT_TOKEN = ("InvalidGrantException", "Invalid token provided")


def _error(fn) -> tuple[str, str]:
    """``(code, message)`` that ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {sorted(result)!r}")


def expect_error(fn, code: str, message: str) -> None:
    """Assert ``fn`` raises exactly ``code`` with exactly ``message``."""
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code}, got {got_code}: {got_message!r}"
    assert got_message == message, f"expected message {message!r}, got {got_message!r}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTokenWithIAM's token-exchange grant with no subjectToken is InvalidRequestException
    "Subject Token is required", even for a client ARN that was never registered, so the missing
    field is caught before any client lookup; supplying one reaches grant lookup instead."""
    sso_oidc = ctx.client("sso-oidc")
    bogus_client_arn = (
        f"arn:aws:sso::{ctx.account}:application/ssoins-0000000000000000/"
        "apl-0000000000000000"
    )

    expect_error(lambda: sso_oidc.create_token_with_iam(
        clientId=bogus_client_arn, grantType=_TOKEN_EXCHANGE_GRANT,
    ), *_NO_SUBJECT_TOKEN)

    # Positive control: the same never-registered client ARN, once subjectToken and
    # subjectTokenType are present, reaches the grant-lookup stage rather than being turned away
    # again at field validation -- proving the first refusal was about the missing field, not a
    # blanket rejection of this client ARN or this grant type.
    expect_error(lambda: sso_oidc.create_token_with_iam(
        clientId=bogus_client_arn, grantType=_TOKEN_EXCHANGE_GRANT,
        subjectToken=ctx.unique_name("sim2real-fabricated-subject-token-"),
        subjectTokenType=_ACCESS_TOKEN_TYPE,
    ), *_BAD_SUBJECT_TOKEN)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
