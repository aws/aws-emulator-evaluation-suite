"""waba-id-pattern-violation-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "waba-id-pattern-violation-rejected"
GROUP = "validation"
SERVICES = ["socialmessaging"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A WABA id that fails the waba-.../arn:...:waba/... pattern is rejected with ValidationException,
    while a well-formed nonexistent one fails with ResourceNotFoundException, each with its exact
    message, so syntax is validated before the lookup."""
    sm = ctx.client("socialmessaging")

    code, msg = _error(lambda: sm.get_linked_whatsapp_business_account(id="not-a-valid-waba-id"))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_msg = "1 validation error detected: Value 'not-a-valid-waba-id' at 'id' failed to satisfy constraint: Member must satisfy regular expression pattern: .*(^waba-.*$)|(^arn:.*:waba/[0-9a-zA-Z]+$).*"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    nonexistent = "waba-00000000000000000000000000000000"
    code2, msg2 = _error(lambda: sm.get_linked_whatsapp_business_account(id=nonexistent))
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
