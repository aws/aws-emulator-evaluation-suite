"""media-id-pattern-violation-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "media-id-pattern-violation-rejected"
GROUP = "validation"
SERVICES = ["socialmessaging"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteWhatsAppMessageMedia rejects a mediaId with spaces or punctuation with ValidationException,
    while a well-formed alphanumeric mediaId on the same nonexistent phone number fails with
    ResourceNotFoundException, each with its exact message."""
    sm = ctx.client("socialmessaging")
    phone_id = "phone-number-id-00000000000000000000000000000000"

    code, msg = _error(
        lambda: sm.delete_whatsapp_message_media(mediaId="bad id!", originationPhoneNumberId=phone_id)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_msg = "1 validation error detected: Value 'bad id!' at 'mediaId' failed to satisfy constraint: Member must satisfy regular expression pattern: [A-Za-z0-9]+"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    code2, msg2 = _error(
        lambda: sm.delete_whatsapp_message_media(mediaId="abcDEF123", originationPhoneNumberId=phone_id)
    )
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2}"
    expected_msg2 = 'Origination phone number id not found for account.'
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
