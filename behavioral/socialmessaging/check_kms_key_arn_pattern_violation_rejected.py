"""kms-key-arn-pattern-violation-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kms-key-arn-pattern-violation-rejected"
GROUP = "validation"
SERVICES = ["socialmessaging"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutWhatsAppBusinessPublicKey rejects a malformed kmsKeyArn with ValidationException, while a
    well-formed KMS key ARN on the same nonexistent phone number fails with ResourceNotFoundException
    from the phone number lookup, each with its exact message; ListLinkedWhatsAppBusinessAccounts answers."""
    sm = ctx.client("socialmessaging")
    phone_id = "phone-number-id-00000000000000000000000000000000"

    code, msg = _error(
        lambda: sm.put_whatsapp_business_public_key(
            originationPhoneNumberId=phone_id, kmsKeyArn="not-a-kms-arn"
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_msg = "1 validation error detected: Value 'not-a-kms-arn' at 'kmsKeyArn' failed to satisfy constraint: Member must satisfy regular expression pattern: arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:(key/.+|alias/.+)"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    valid_kms_arn = "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    code2, msg2 = _error(
        lambda: sm.put_whatsapp_business_public_key(
            originationPhoneNumberId=phone_id, kmsKeyArn=valid_kms_arn
        )
    )
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2}"
    expected_msg2 = 'Origination phone number id not found for account.'
    assert msg2 == expected_msg2, f"expected message {expected_msg2!r}, got {msg2!r}"

    # Positive control: the service answers other calls, so the two rejections above
    # discriminate on input rather than deny every call.
    response = sm.list_linked_whatsapp_business_accounts()
    assert "linkedAccounts" in response, f"expected linkedAccounts in response, got {response!r}"


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
