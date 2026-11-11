"""template-definition-exceeds-max-bytes-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "template-definition-exceeds-max-bytes-rejected"
GROUP = "overly-permissive"
SERVICES = ["socialmessaging"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateWhatsAppMessageTemplate rejects a templateDefinition one byte over its 6000-byte maximum
    with ValidationException, while a small well-formed one on the same nonexistent WABA fails with
    ResourceNotFoundException, each with its exact message."""
    sm = ctx.client("socialmessaging")
    waba_id = "waba-00000000000000000000000000000000"

    oversized = b'{"template":"' + (b"a" * 6100) + b'"}'
    assert len(oversized) > 6000, f"test payload must exceed the 6000-byte limit, got {len(oversized)}"
    code, msg = _error(
        lambda: sm.create_whatsapp_message_template(id=waba_id, templateDefinition=oversized)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_msg = "1 validation error detected: Value at 'templateDefinition' failed to satisfy constraint: Member must have length less than or equal to 6000"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    small = b'{"name":"x"}'
    assert len(small) <= 6000, f"control payload must be within the 6000-byte limit, got {len(small)}"
    code2, msg2 = _error(
        lambda: sm.create_whatsapp_message_template(id=waba_id, templateDefinition=small)
    )
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2}"
    expected_msg2 = 'Id not found for account.'
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
