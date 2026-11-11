"""batch-get-invoice-profile-unlinked-account-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-get-invoice-profile-unlinked-account-rejected"
GROUP = "overly-permissive"
SERVICES = ["invoicing"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchGetInvoiceProfile returns the caller's own account profile, while a request
    that adds an account outside the caller's organization fails with
    AccessDeniedException and its exact message naming that account."""

    invoicing = ctx.client("invoicing")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    own = invoicing.batch_get_invoice_profile(AccountIds=[account_id])
    assert any(p["AccountId"] == account_id for p in own["Profiles"]), (
        f"expected a profile for the caller's own linked account {account_id}, got {own['Profiles']!r}"
    )

    # Well-formed (12 digits) but not a linked member of this org.
    unlinked_account_id = "111111111111" if account_id != "111111111111" else "222222222222"
    error = _client_error(
        lambda: invoicing.batch_get_invoice_profile(
            AccountIds=[account_id, unlinked_account_id]
        )
    )
    code = error["Code"]
    message = error.get("Message", "")
    assert code == "AccessDeniedException", (
        f"expected AccessDeniedException for an unlinked account id, got {code}: {message}"
    )
    expected_message = (
        f"Account {account_id} is not authorized to access resources for account {unlinked_account_id}"
    )
    assert message == expected_message, (
        f"expected AccessDeniedException message {expected_message!r}, got {message!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(
        f"real AWS rejects an unlinked AccountIds entry, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
