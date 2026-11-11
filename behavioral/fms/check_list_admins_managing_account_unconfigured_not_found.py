"""list-admins-managing-account-unconfigured-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-admins-managing-account-unconfigured-not-found"
GROUP = "unconfigured-state"
SERVICES = ["fms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListAdminsManagingAccount raises ResourceNotFoundException when no Firewall
    Manager administrator is currently managing the calling account.
    """
    fms = ctx.client("fms")
    code, message = _error_code(lambda: fms.list_admins_managing_account())
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "The referenced item does not exist.", (
        f"expected the not-configured-admin message, got {message!r}"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        raise AssertionError("expected ListAdminsManagingAccount to raise, it succeeded")
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
