"""receipt-filter-invalid-cidr-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "receipt-filter-invalid-cidr-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ses']

def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _require_receipt_region(ctx):
    """SES email receiving (receipt filters) is region-limited; us-west-2 offers it."""
    if ctx.region not in ("us-east-1", "us-west-2", "eu-west-1"):
        raise AssertionError(f"SES email receiving (receipt filters) is unavailable in {ctx.region}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateReceiptFilter must reject a malformed CIDR block instead of storing it."""
    ses = ctx.client("ses")
    _require_receipt_region(ctx)

    # Positive control: a well-formed filter must succeed, so the negative below cannot be
    # indistinguishable from "this account/target rejects every CreateReceiptFilter call".
    good_name = ctx.unique_name("sim2real-behav-filter-good-")
    ses.create_receipt_filter(
        Filter={"Name": good_name, "IpFilter": {"Cidr": "203.0.113.0/24", "Policy": "Block"}}
    )
    ctx.on_cleanup(lambda: ses.delete_receipt_filter(FilterName=good_name))
    names = [f["Name"] for f in ses.list_receipt_filters()["Filters"]]
    assert good_name in names, f"positive control: valid receipt filter not persisted: {good_name}"

    bad_name = ctx.unique_name("sim2real-behav-filter-bad-")
    err, msg = _err(
        lambda: ses.create_receipt_filter(
            Filter={"Name": bad_name, "IpFilter": {"Cidr": "999.999.999.999/99", "Policy": "Block"}}
        )
    )
    assert err == "InvalidParameterValue", (
        f"expected InvalidParameterValue for a malformed CIDR, got {err!r}: {msg!r}"
    )
    expected_msg = "Invalid CIDR block: 999.999.999.999/99"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    names = [f["Name"] for f in ses.list_receipt_filters()["Filters"]]
    assert good_name in names, f"positive control filter disappeared: {good_name}"
    assert bad_name not in names, f"a rejected receipt filter was persisted: {bad_name}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
