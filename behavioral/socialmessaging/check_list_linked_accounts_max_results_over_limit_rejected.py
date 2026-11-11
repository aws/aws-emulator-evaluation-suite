"""list-linked-accounts-max-results-over-limit-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-linked-accounts-max-results-over-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["socialmessaging"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListLinkedWhatsAppBusinessAccounts rejects maxResults=101 with ValidationException and its
    exact message, and accepts the boundary value 100."""
    sm = ctx.client("socialmessaging")

    code, msg = _error(lambda: sm.list_linked_whatsapp_business_accounts(maxResults=101))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_msg = "1 validation error detected: Value '101' at 'maxResults' failed to satisfy constraint: Member must have value less than or equal to 100"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # Positive control: the boundary value itself must succeed.
    response = sm.list_linked_whatsapp_business_accounts(maxResults=100)
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
