"""flow-categories-exceeds-max-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "flow-categories-exceeds-max-rejected"
GROUP = "overly-permissive"
SERVICES = ["socialmessaging"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateWhatsAppFlow rejects 10 categories (the maximum is 9) with ValidationException, while
    exactly 9 pass validation and fail with ResourceNotFoundException for the nonexistent WABA,
    each with its exact message."""
    sm = ctx.client("socialmessaging")
    waba_id = "waba-00000000000000000000000000000000"

    code, msg = _error(
        lambda: sm.create_whatsapp_flow(
            id=waba_id, flowName="sim2real-test-flow", categories=["OTHER"] * 10
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_msg = "1 validation error detected: Value '[OTHER, OTHER, OTHER, OTHER, OTHER, OTHER, OTHER, OTHER, OTHER, OTHER]' at 'categories' failed to satisfy constraint: Member must have length less than or equal to 9"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    code2, msg2 = _error(
        lambda: sm.create_whatsapp_flow(
            id=waba_id, flowName="sim2real-test-flow", categories=["OTHER"] * 9
        )
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
