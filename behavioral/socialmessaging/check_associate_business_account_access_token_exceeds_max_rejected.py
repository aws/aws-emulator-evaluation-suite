"""associate-business-account-access-token-exceeds-max-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-business-account-access-token-exceeds-max-rejected"
GROUP = "validation"
SERVICES = ["socialmessaging"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateWhatsAppBusinessAccount rejects a signupCallback.accessToken of 1001 characters,
    one over the 1000 maximum, with ValidationException, while a token within the limit passes
    the length check and fails callback verification with AccessDeniedException, each with its exact message."""
    sm = ctx.client("socialmessaging")

    too_long_token = "a" * 1001
    code, msg = _error(
        lambda: sm.associate_whatsapp_business_account(
            signupCallback={"accessToken": too_long_token}
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_msg = "1 validation error detected: Value at 'signupCallback.accessToken' failed to satisfy constraint: Member must have length less than or equal to 1000"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    valid_length_token = "expired-or-invalid-meta-access-token-000000"
    assert len(valid_length_token) <= 1000
    code2, msg2 = _error(
        lambda: sm.associate_whatsapp_business_account(
            signupCallback={
                "accessToken": valid_length_token,
                "callbackUrl": "https://example.com/callback",
            }
        )
    )
    assert code2 == "AccessDeniedException", f"expected AccessDeniedException, got {code2}"
    expected_msg2 = 'CSRF header does not exist'
    assert msg2 == expected_msg2, f"expected message {expected_msg2!r}, got {msg2!r}"


def _error(fn):
    """Call fn(); return the (code, message) of its botocore error. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
