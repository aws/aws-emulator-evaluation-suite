"""create-custom-line-item-requires-payer-account."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-custom-line-item-requires-payer-account"
GROUP = "overly-permissive"
SERVICES = ["billingconductor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """From a non-payer account, ListCustomLineItems and CreateCustomLineItem (with an invalid ChargeDetails
    and a nonexistent billing group) both fail with AccessDeniedException "Account <id> is not authorized to
    call <op>. Only payer account is authorized": the payer gate runs before body validation."""
    bc = ctx.client("billingconductor")
    account_id = _caller_account_id(ctx)
    bad_name = ctx.unique_name("sim2real-bc-badcli-")
    fake_bg_arn = f"arn:aws:billingconductor::{account_id}:billinggroup/sim2real0002"

    list_code, list_message = _error_info(
        lambda: bc.list_custom_line_items(Filters={"Names": [bad_name]})
    )
    assert list_code == "AccessDeniedException", (
        f"expected the read side of the same gate to be denied too, got: "
        f"{list_code} ({list_message})"
    )
    expected_list = f"Account {account_id} is not authorized to call ListCustomLineItems. Only payer account is authorized"
    assert list_message == expected_list, (
        f"ListCustomLineItems: unexpected message: {list_message!r}, expected {expected_list!r}"
    )

    code, message = _error_info(
        lambda: bc.create_custom_line_item(
            Name=bad_name,
            Description="both flat and percentage set",
            BillingGroupArn=fake_bg_arn,
            ChargeDetails={
                "Type": "FEE",
                "Flat": {"ChargeValue": 10.0},
                "Percentage": {"PercentageValue": 5.0},
            },
        )
    )
    assert code == "AccessDeniedException", f"unexpected error code: {code} ({message})"
    expected = f"Account {account_id} is not authorized to call CreateCustomLineItem. Only payer account is authorized"
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
