"""phone-number-opt-out-state."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "phone-number-opt-out-state"
GROUP = 'sms'
SERVICES = ['sns']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CheckIfPhoneNumberIsOptedOut reports False for an unused number and ListPhoneNumbersOptedOut agrees."""
    sns = ctx.client("sns")
    suffix = uuid.uuid4().int % 10000
    phone_number = f"+1500555{suffix:04d}"

    resp = sns.check_if_phone_number_is_opted_out(phoneNumber=phone_number)
    assert resp["isOptedOut"] is False, f"unused number should not be opted out, got {resp}"

    resp_again = sns.check_if_phone_number_is_opted_out(phoneNumber=phone_number)
    assert resp_again["isOptedOut"] is False, (
        f"a read must not flip opt-out state: first call False, second call got {resp_again}"
    )

    opted_out = set()
    for page in sns.get_paginator("list_phone_numbers_opted_out").paginate():
        opted_out.update(page.get("phoneNumbers", []))
    assert phone_number not in opted_out, f"{phone_number} unexpectedly in opt-out list"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
