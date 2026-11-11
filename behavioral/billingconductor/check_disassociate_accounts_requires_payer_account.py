"""disassociate-accounts-requires-payer-account."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "disassociate-accounts-requires-payer-account"
GROUP = "overly-permissive"
SERVICES = ["billingconductor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """From a non-payer account, DisassociateAccounts on a nonexistent billing group fails with
    AccessDeniedException "Account <id> is not authorized to call DisassociateAccounts. Only payer account is
    authorized", while TagResource on the same arn fails with NotFoundException "Resource was not found"."""
    bc = ctx.client("billingconductor")
    account_id = _caller_account_id(ctx)
    fake_bg_arn = f"arn:aws:billingconductor::{account_id}:billinggroup/BOGUS00006"

    control_code, control_msg = _error_info(
        lambda: bc.tag_resource(ResourceArn=fake_bg_arn, Tags={"env": "sim2real"})
    )
    assert control_code == "NotFoundException", (
        f"positive control TagResource: expected NotFoundException, got {control_code} ({control_msg})"
    )
    assert control_msg == "Resource was not found", (
        f"positive control TagResource: unexpected message: {control_msg!r}"
    )

    code, message = _error_info(
        lambda: bc.disassociate_accounts(Arn=fake_bg_arn, AccountIds=["111111111111"])
    )
    assert code == "AccessDeniedException", f"unexpected error code: {code} ({message})"
    expected = f"Account {account_id} is not authorized to call DisassociateAccounts. Only payer account is authorized"
    assert message == expected, f"unexpected message: {message!r}, expected {expected!r}"


def _caller_account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _error_info(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return (err["Code"], err.get("Message"))
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
