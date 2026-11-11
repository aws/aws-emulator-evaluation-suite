"""create-receipt-rule-invalid-header-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-receipt-rule-invalid-header-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["ses"]


def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateReceiptRule rejects an AddHeaderAction HeaderName outside the documented
    alphanumeric-and-dash charset and persists no rule; a well-formed header name is accepted."""
    ses = ctx.client("ses")
    rule_set_name = ctx.unique_name("sim2real-behav-ses-hdr-rs-")
    ses.create_receipt_rule_set(RuleSetName=rule_set_name)
    ctx.on_cleanup(lambda: ses.delete_receipt_rule_set(RuleSetName=rule_set_name))

    good_rule_name = ctx.unique_name("sim2real-behav-ses-hdr-good-")
    ses.create_receipt_rule(
        RuleSetName=rule_set_name,
        Rule={
            "Name": good_rule_name,
            "Enabled": True,
            "ScanEnabled": False,
            "Actions": [{"AddHeaderAction": {"HeaderName": "X-Sim2Real-Probe", "HeaderValue": "ok"}}],
        },
    )
    ctx.on_cleanup(lambda: ses.delete_receipt_rule(RuleSetName=rule_set_name, RuleName=good_rule_name))

    names_before = {
        r["Name"] for r in ses.describe_receipt_rule_set(RuleSetName=rule_set_name)["Rules"]
    }
    assert good_rule_name in names_before, (
        f"positive control: well-formed rule {good_rule_name!r} was not persisted: {names_before!r}"
    )

    # The API model declares no pattern/length on HeaderName; the charset limit is documented only.
    bad_rule_name = ctx.unique_name("sim2real-behav-ses-hdr-bad-")
    err = _err(
        lambda: ses.create_receipt_rule(
            RuleSetName=rule_set_name,
            Rule={
                "Name": bad_rule_name,
                "Enabled": True,
                "ScanEnabled": False,
                "Actions": [
                    {"AddHeaderAction": {"HeaderName": "X Sim2Real Probe!", "HeaderValue": "bad"}}
                ],
            },
        )
    )
    expected = ("InvalidParameterValue", "Invalid header name: X Sim2Real Probe!")
    assert err == expected, (
        f"expected {expected!r} for a header name outside [A-Za-z0-9-], got {err!r}"
    )

    names_after = {
        r["Name"] for r in ses.describe_receipt_rule_set(RuleSetName=rule_set_name)["Rules"]
    }
    assert bad_rule_name not in names_after, (
        f"a rejected CreateReceiptRule call still persisted rule {bad_rule_name!r}: {names_after!r}"
    )
    assert good_rule_name in names_after, (
        f"positive control rule {good_rule_name!r} disappeared after the rejected call: {names_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
