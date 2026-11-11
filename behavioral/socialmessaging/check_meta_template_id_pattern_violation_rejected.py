"""meta-template-id-pattern-violation-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "meta-template-id-pattern-violation-rejected"
GROUP = "validation"
SERVICES = ["socialmessaging"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetWhatsAppMessageTemplate rejects a non-numeric metaTemplateId with ValidationException, while
    a numeric one on the same nonexistent WABA fails with ResourceNotFoundException, each with its
    exact message."""
    sm = ctx.client("socialmessaging")
    waba_id = "waba-00000000000000000000000000000000"

    code, msg = _error(
        lambda: sm.get_whatsapp_message_template(id=waba_id, metaTemplateId="abc")
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_msg = "1 validation error detected: Value 'abc' at 'metaTemplateId' failed to satisfy constraint: Member must satisfy regular expression pattern: [0-9]+"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    code2, msg2 = _error(
        lambda: sm.get_whatsapp_message_template(id=waba_id, metaTemplateId="123456789012345")
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
