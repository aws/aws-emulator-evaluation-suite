"""cross-resource-type-id-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cross-resource-type-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["socialmessaging"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetLinkedWhatsAppBusinessAccountPhoneNumber rejects a well-formed WABA id passed as
    the phone number id with ValidationException, while a well-formed but nonexistent
    phone number id fails with ResourceNotFoundException, each with its exact message."""
    sm = ctx.client("socialmessaging")
    waba_shaped_id = "waba-00000000000000000000000000000000"

    code, msg = _error(
        lambda: sm.get_linked_whatsapp_business_account_phone_number(id=waba_shaped_id)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_msg = f"1 validation error detected: Value '{waba_shaped_id}' at 'id' failed to satisfy constraint: Member must satisfy regular expression pattern: .*(^phone-number-id-.*$)|(^arn:.*:phone-number-id/[0-9a-zA-Z]+$).*"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    phone_shaped_id = "phone-number-id-00000000000000000000000000000000"
    code2, msg2 = _error(
        lambda: sm.get_linked_whatsapp_business_account_phone_number(id=phone_shaped_id)
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
