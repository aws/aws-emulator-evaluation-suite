"""get-linked-waba-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-linked-waba-not-found"
GROUP = "not-found"
SERVICES = ["socialmessaging"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A well-formed WABA id that was never linked to this account fails with
    ResourceNotFoundException, not a generic error, and the account itself remains
    usable afterward (the positive control: listing linked accounts still succeeds)."""
    sm = ctx.client("socialmessaging")
    nonexistent = "waba-00000000000000000000000000000000"

    code, msg = _error(lambda: sm.get_linked_whatsapp_business_account(id=nonexistent))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_msg = 'Requested resource not found.'
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # Positive control: the account is otherwise unaffected and functional.
    response = sm.list_linked_whatsapp_business_accounts()
    assert "linkedAccounts" in response
    assert nonexistent not in [a["id"] for a in response["linkedAccounts"]]


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
