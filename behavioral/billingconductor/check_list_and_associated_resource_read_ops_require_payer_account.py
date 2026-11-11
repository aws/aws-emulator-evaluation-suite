"""list-and-associated-resource-read-ops-require-payer-account."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-and-associated-resource-read-ops-require-payer-account"
GROUP = "overly-permissive"
SERVICES = ["billingconductor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """From a non-payer account, ListCustomLineItems, ListCustomLineItemVersions and
    ListResourcesAssociatedToCustomLineItem each fail with AccessDeniedException "Account <id> is not
    authorized to call <op>. Only payer account is authorized", not an IAM deny text or an empty page."""
    bc = ctx.client("billingconductor")
    account_id = _caller_account_id(ctx)
    fake_cli_arn = f"arn:aws:billingconductor::{account_id}:customlineitem/BOGUS00007"

    code_a, msg_a = _error_info(lambda: bc.list_custom_line_items(MaxResults=5))
    assert code_a == "AccessDeniedException", f"ListCustomLineItems: expected AccessDeniedException, got {code_a}"
    expected_a = f"Account {account_id} is not authorized to call ListCustomLineItems. Only payer account is authorized"
    assert msg_a == expected_a, (
        f"ListCustomLineItems: expected AccessDeniedException citing the payer-account "
        f"restriction, got {code_a} ({msg_a})"
    )

    code_b, msg_b = _error_info(
        lambda: bc.list_custom_line_item_versions(Arn=fake_cli_arn)
    )
    assert code_b == "AccessDeniedException", f"ListCustomLineItemVersions: expected AccessDeniedException, got {code_b}"
    expected_b = f"Account {account_id} is not authorized to call ListCustomLineItemVersions. Only payer account is authorized"
    assert msg_b == expected_b, (
        f"ListCustomLineItemVersions: expected AccessDeniedException citing the "
        f"payer-account restriction, got {code_b} ({msg_b})"
    )

    code_c, msg_c = _error_info(
        lambda: bc.list_resources_associated_to_custom_line_item(Arn=fake_cli_arn)
    )
    assert code_c == "AccessDeniedException", f"ListResourcesAssociatedToCustomLineItem: expected AccessDeniedException, got {code_c}"
    expected_c = f"Account {account_id} is not authorized to call ListResourcesAssociatedToCustomLineItem. Only payer account is authorized"
    assert msg_c == expected_c, (
        f"ListResourcesAssociatedToCustomLineItem: expected AccessDeniedException citing "
        f"the payer-account restriction, got {code_c} ({msg_c})"
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
