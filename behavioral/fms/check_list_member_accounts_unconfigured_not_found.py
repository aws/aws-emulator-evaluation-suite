"""list-member-accounts-unconfigured-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-member-accounts-unconfigured-not-found"
GROUP = "unconfigured-state"
SERVICES = ["fms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """With no Firewall Manager admin, ListMemberAccounts fails with AccessDeniedException
    "No default admin could be found for account <id> in Region <region>", not an IAM "is not authorized" denial."""
    fms = ctx.client("fms")
    code, message = _client_error(lambda: fms.list_member_accounts())
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}: {message}"
    assert message == f"No default admin could be found for account {ctx.account} in Region {ctx.region}", f"unexpected AccessDeniedException message: {message!r}"


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
