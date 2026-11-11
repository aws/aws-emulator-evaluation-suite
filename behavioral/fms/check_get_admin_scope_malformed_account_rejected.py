"""get-admin-scope-malformed-account-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-admin-scope-malformed-account-rejected"
GROUP = "validation"
SERVICES = ["fms", "organizations"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAdminScope with AdminAccount "not-an-account-id" fails with ValidationException and the exact pattern
    message, while a well-formed account id fails with InvalidOperationException naming the caller as not the
    organization's management account."""
    fms = ctx.client("fms")

    malformed_code, malformed_message = _client_error(lambda: fms.get_admin_scope(AdminAccount="not-an-account-id"))
    assert malformed_code == "ValidationException", f"expected ValidationException, got {malformed_code}"
    assert malformed_message == (
        "1 validation error detected: Value 'not-an-account-id' at 'adminAccount' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: ^[0-9]+$"
    ), f"unexpected ValidationException message: {malformed_message!r}"

    # a syntactically valid, 12-digit account id that is (almost certainly) not a
    # registered Firewall Manager administrator for this caller's organization
    wellformed_unregistered = "999999999999"
    management_account = ctx.client("organizations").describe_organization()["Organization"][
        "MasterAccountId"
    ]
    notfound_code, notfound_message = _client_error(lambda: fms.get_admin_scope(AdminAccount=wellformed_unregistered))
    assert notfound_code == "InvalidOperationException", (
        f"expected InvalidOperationException for well-formed unregistered account, got {notfound_code}"
    )
    assert notfound_message == (
        f"{ctx.account} is not the management account of the Organization but is attempting to perform "
        f"an action that only the Organization management account can perform. The Organization "
        f"management account is {management_account}"
    ), f"unexpected InvalidOperationException message: {notfound_message!r}"


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
