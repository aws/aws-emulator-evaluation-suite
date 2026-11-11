"""waba-id-exceeds-max-length-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "waba-id-exceeds-max-length-rejected"
GROUP = "validation"
SERVICES = ["socialmessaging"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A 116-character WABA id, one over the 115 maximum, is rejected with ValidationException, while
    a well-formed id of exactly 115 characters passes validation and fails with
    ResourceNotFoundException, each with its exact message."""
    sm = ctx.client("socialmessaging")

    too_long = "waba-" + ("0" * 111)  # 5 + 111 = 116 chars, exceeds max of 115
    assert len(too_long) == 116, f"expected a 116-char id, built {len(too_long)}"
    code, msg = _error(lambda: sm.get_linked_whatsapp_business_account(id=too_long))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_msg = f"1 validation error detected: Value '{too_long}' at 'id' failed to satisfy constraint: Member must have length less than or equal to 115"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    at_max = "waba-" + ("0" * 110)  # 5 + 110 = 115 chars, exactly at max
    assert len(at_max) == 115, f"expected a 115-char id, built {len(at_max)}"
    code2, msg2 = _error(lambda: sm.get_linked_whatsapp_business_account(id=at_max))
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2}"
    expected_msg2 = 'Requested resource not found.'
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
