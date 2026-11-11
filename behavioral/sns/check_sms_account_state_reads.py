"""sms-account-state-reads."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "sms-account-state-reads"
GROUP = 'sms'
SERVICES = ['sns']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Account-level SMS reads report real state: IsInSandbox is a bool, the account-wide
    MonthlySpendLimit attribute is a numeric string, and origination numbers are a list.
    """
    sns = ctx.client("sns")

    status = sns.get_sms_sandbox_account_status()
    assert isinstance(status["IsInSandbox"], bool), status

    attrs = sns.get_sms_attributes()["attributes"]
    assert isinstance(attrs, dict), attrs
    assert "MonthlySpendLimit" in attrs, (
        f"expected the account-wide MonthlySpendLimit default attribute, got keys {sorted(attrs)}"
    )
    assert attrs["MonthlySpendLimit"].isdigit(), (
        f"MonthlySpendLimit should be a numeric string, got {attrs['MonthlySpendLimit']!r}"
    )

    numbers = sns.list_origination_numbers()["PhoneNumbers"]
    assert isinstance(numbers, list), numbers


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
