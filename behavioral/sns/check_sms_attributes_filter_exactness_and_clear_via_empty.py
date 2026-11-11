"""sms-attributes-filter-exactness-and-clear-via-empty."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "sms-attributes-filter-exactness-and-clear-via-empty"
GROUP = 'sms'
SERVICES = ['sns']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:sns-sms-attributes")
def run(ctx) -> None:
    """GetSMSAttributes filtered to one name returns exactly that key while an unfiltered read has
    more, and SetSMSAttributes with an empty value removes the attribute rather than blanking it."""
    sns = ctx.client("sns")

    before = sns.get_sms_attributes()["attributes"]
    original_type = before.get("DefaultSMSType")
    ctx.on_cleanup(
        lambda: sns.set_sms_attributes(attributes={"DefaultSMSType": original_type or ""})
    )

    # Real AWS caps MonthlySpendLimit per account (often at "1"), so the filter/clear behavior
    # is exercised on DefaultSMSType, which carries no account-specific quota.
    sns.set_sms_attributes(attributes={"DefaultSMSType": "Transactional"})

    selected = sns.get_sms_attributes(attributes=["DefaultSMSType"])["attributes"]
    assert selected == {"DefaultSMSType": "Transactional"}, (
        f"GetSMSAttributes(attributes=['DefaultSMSType']) must return EXACTLY that "
        f"key, got {selected!r}"
    )

    everything = sns.get_sms_attributes()["attributes"]
    assert everything.get("DefaultSMSType") == "Transactional", (
        f"expected DefaultSMSType='Transactional' in the unfiltered read, got {everything!r}"
    )
    assert "MonthlySpendLimit" in everything, (
        f"the unfiltered read must still carry account attributes outside the filter, "
        f"got {everything!r}"
    )

    sns.set_sms_attributes(attributes={"DefaultSMSType": ""})

    after = sns.get_sms_attributes()["attributes"]
    assert "DefaultSMSType" not in after, (
        f"SetSMSAttributes with an empty value must remove DefaultSMSType entirely "
        f"(not leave it present and blank), got {after!r}"
    )
    assert "MonthlySpendLimit" in after, (
        f"clearing DefaultSMSType must not disturb other account attributes, got {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
