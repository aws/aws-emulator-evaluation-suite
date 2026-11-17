"""enable-organization-admin-account-format-checked-before-authority."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "enable-organization-admin-account-format-checked-before-authority"
GROUP = "overly-permissive"
SERVICES = ["securityhub"]

_BAD_ACCOUNT_ID = "sim2real-not-numeric"
_INVALID_FORMAT = ("InvalidInputException", f"Invalid accountId: {_BAD_ACCOUNT_ID}")
_NOT_AUTHORIZED = ("InvalidAccessException", "You don't have permissions to perform the requested operation")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:securityhub")
def run(ctx) -> None:
    """EnableOrganizationAdminAccount rejects a non-numeric AdminAccountId with InvalidInputException
    before any organization-authority check; a syntactically valid 12-digit id instead reaches that
    check and is refused there with InvalidAccessException."""
    sh = ctx.client("securityhub")
    _ensure_hub_enabled(ctx, sh)

    expect_error(lambda: sh.enable_organization_admin_account(AdminAccountId=_BAD_ACCOUNT_ID), *_INVALID_FORMAT)

    # Legal neighbor: a well-formed 12-digit account id passes the format check and reaches the
    # later organization-authority check instead, which this (non-management) account also fails.
    expect_error(lambda: sh.enable_organization_admin_account(AdminAccountId=ctx.account), *_NOT_AUTHORIZED)

    # The account's own hub subscription is unaffected by either rejected call.
    hub = sh.describe_hub()
    expected_arn = f"arn:aws:securityhub:{ctx.region}:{ctx.account}:hub/default"
    assert hub.get("HubArn") == expected_arn, f"expected hub ARN {expected_arn!r}, got {hub.get('HubArn')!r}"


def _ensure_hub_enabled(ctx, sh):
    """Enable the account's Security Hub subscription unless it is already active, and register
    cleanup to restore the prior (disabled) state only when this call is what enabled it."""
    try:
        sh.describe_hub()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidAccessException":
            raise
    else:
        return
    sh.enable_security_hub(EnableDefaultStandards=False)
    ctx.on_cleanup(_teardown(sh.disable_security_hub, "ResourceNotFoundException"))


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` codes mean
    the resource is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def expect_error(fn, code, message):
    """Call fn(); assert it raises exactly (code, message). An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        actual_code = exc.response["Error"]["Code"]
        actual_message = exc.response["Error"].get("Message")
        assert actual_code == code, f"expected {code}, got {actual_code} ({actual_message})"
        assert actual_message == message, f"expected message {message!r}, got {actual_message!r}"
        return
    raise AssertionError(f"expected {code} ({message!r}), but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
