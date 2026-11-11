"""batch-associate-and-disassociate-resources-require-payer-account."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-associate-and-disassociate-resources-require-payer-account"
GROUP = "overly-permissive"
SERVICES = ["billingconductor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """From a non-payer account, BatchAssociateResourcesToCustomLineItem and
    BatchDisassociateResourcesFromCustomLineItem on nonexistent ARNs fail at the top level with
    AccessDeniedException "Account <id> is not authorized to call <op>. Only payer account is authorized"."""
    bc = ctx.client("billingconductor")
    account_id = _caller_account_id(ctx)
    fake_cli_arn = f"arn:aws:billingconductor::{account_id}:customlineitem/BOGUS00005"
    fake_bg_arn = f"arn:aws:billingconductor::{account_id}:billinggroup/BOGUS00005"

    code_a, msg_a = _error_info(
        lambda: bc.batch_associate_resources_to_custom_line_item(
            TargetArn=fake_cli_arn, ResourceArns=[fake_bg_arn]
        )
    )
    assert code_a == "AccessDeniedException", (
        f"BatchAssociateResourcesToCustomLineItem: unexpected code: {code_a} ({msg_a})"
    )
    expected_a = f"Account {account_id} is not authorized to call BatchAssociateResourcesToCustomLineItem. Only payer account is authorized"
    assert msg_a == expected_a, (
        f"BatchAssociateResourcesToCustomLineItem: expected the payer-account denial "
        f"{expected_a!r}, got {msg_a!r}"
    )

    code_b, msg_b = _error_info(
        lambda: bc.batch_disassociate_resources_from_custom_line_item(
            TargetArn=fake_cli_arn, ResourceArns=[fake_bg_arn]
        )
    )
    assert code_b == "AccessDeniedException", (
        f"BatchDisassociateResourcesFromCustomLineItem: unexpected code: {code_b} ({msg_b})"
    )
    expected_b = f"Account {account_id} is not authorized to call BatchDisassociateResourcesFromCustomLineItem. Only payer account is authorized"
    assert msg_b == expected_b, (
        f"BatchDisassociateResourcesFromCustomLineItem: expected the payer-account denial "
        f"{expected_b!r}, got {msg_b!r}"
    )


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
