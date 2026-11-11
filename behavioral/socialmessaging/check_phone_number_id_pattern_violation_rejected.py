"""phone-number-id-pattern-violation-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "phone-number-id-pattern-violation-rejected"
GROUP = "validation"
SERVICES = ["socialmessaging"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetWhatsAppBusinessPublicKey rejects a phone number id that fails the documented pattern with
    ValidationException and a well-formed nonexistent one with ResourceNotFoundException "Origination
    phone number id not found for account."; a linked WABA's first phone number, if any, is accepted."""
    sm = ctx.client("socialmessaging")

    code, msg = _error(lambda: sm.get_whatsapp_business_public_key(originationPhoneNumberId="12345"))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_msg = "1 validation error detected: Value '12345' at 'originationPhoneNumberId' failed to satisfy constraint: Member must satisfy regular expression pattern: .*(^phone-number-id-.*$)|(^arn:.*:phone-number-id/[0-9a-zA-Z]+$).*"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    nonexistent = "phone-number-id-00000000000000000000000000000000"
    code2, msg2 = _error(lambda: sm.get_whatsapp_business_public_key(originationPhoneNumberId=nonexistent))
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2}"
    expected_msg2 = 'Origination phone number id not found for account.'
    assert msg2 == expected_msg2, f"expected message {expected_msg2!r}, got {msg2!r}"

    linked = sm.list_linked_whatsapp_business_accounts().get("linkedAccounts", [])
    if linked:
        account = sm.get_linked_whatsapp_business_account(id=linked[0]["id"])["account"]
        phone_numbers = account.get("phoneNumbers", [])
        if phone_numbers:
            real_phone_id = phone_numbers[0]["phoneNumberId"]
            try:
                sm.get_whatsapp_business_public_key(originationPhoneNumberId=real_phone_id)
            except ClientError as exc:
                real_code = exc.response.get("Error", {}).get("Code")
                raise AssertionError(
                    f"expected a real linked phone number id ({real_phone_id!r}) to be "
                    f"accepted, got {real_code}"
                ) from exc


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
