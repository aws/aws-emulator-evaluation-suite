"""list-admin-accounts-for-organization-unconfigured-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-admin-accounts-for-organization-unconfigured-not-found"
GROUP = "unconfigured-state"
SERVICES = ["fms", "organizations"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAdminAccount fails with ResourceNotFoundException and an empty message, while ListAdminAccountsForOrganization
    fails with InvalidOperationException naming the caller as not the organization's management account."""
    fms = ctx.client("fms")

    admin_account_code, admin_account_message = _client_error(lambda: fms.get_admin_account())
    assert admin_account_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetAdminAccount (positive control), "
        f"got {admin_account_code}"
    )
    # GetAdminAccount's not-found error carries an empty message.
    assert admin_account_message == "", f"unexpected ResourceNotFoundException message: {admin_account_message!r}"

    management_account = ctx.client("organizations").describe_organization()["Organization"][
        "MasterAccountId"
    ]
    code, message = _client_error(lambda: fms.list_admin_accounts_for_organization())
    assert code == "InvalidOperationException", f"expected InvalidOperationException, got {code}"
    assert message == (
        f"{ctx.account} is not the management account of the Organization but is attempting to perform "
        f"an action that only the Organization management account can perform. The Organization "
        f"management account is {management_account}"
    ), f"unexpected InvalidOperationException message: {message!r}"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
