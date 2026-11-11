"""get-primary-email-update-status-never-started-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-primary-email-update-status-never-started-not-found"
GROUP = "error-semantics"
SERVICES = ["account"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetPrimaryEmailUpdateStatus on an account where no email update was ever started is rejected
    with ValidationException "No email update found for account", while GetAccountInformation still
    succeeds, so the rejection is specific to this operation."""
    account = ctx.client("account")

    own_account_id = account.get_account_information()["AccountId"]

    code, message = _error_code(lambda: account.get_primary_email_update_status())
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == "No email update found for account", message

    # positive control: an ordinary, unrelated account call still succeeds
    info = account.get_account_information()
    assert info["AccountId"] == own_account_id


def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, so a target
    accepting what AWS refuses cannot be read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
