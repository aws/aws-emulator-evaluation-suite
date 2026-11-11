"""get-sms-attributes-unknown-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-sms-attributes-unknown-name-rejected"
GROUP = 'overly-permissive'
SERVICES = ['sns']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetSMSAttributes rejects a filter naming an attribute SNS does not define,
    rather than silently answering with that key absent."""
    sns = ctx.client("sns")

    # Positive control: a real attribute name, filtered, is answered normally. This
    # proves GetSMSAttributes' filter argument works in this account before the
    # negative below is meaningful.
    control = sns.get_sms_attributes(attributes=["MonthlySpendLimit"])["attributes"]
    assert control.get("MonthlySpendLimit") is not None, (
        f"positive control failed: expected a MonthlySpendLimit value, got {control!r}"
    )

    try:
        result = sns.get_sms_attributes(attributes=["NotARealSmsAttribute"])
    except ClientError as exc:
        code, message = exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    else:
        raise AssertionError(
            f"GetSMSAttributes with an unknown attribute filter name was expected to be "
            f"rejected, but it SUCCEEDED with {result.get('attributes')!r}"
        )
    expected = "Unknown attribute requested: NotARealSmsAttribute"
    assert (code, message) == ("InvalidParameter", expected), (
        f"expected InvalidParameter {expected!r} for an unknown SMS attribute filter name, got "
        f"{code!r} {message!r}"
    )

    # Effect absent: the rejected filter must not have added the unknown name, or
    # disturbed the real attribute it was asked alongside.
    after = sns.get_sms_attributes(attributes=["MonthlySpendLimit"])["attributes"]
    assert after == control, (
        f"a rejected GetSMSAttributes call must not change subsequent reads: "
        f"before={control!r} after={after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
