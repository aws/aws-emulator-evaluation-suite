"""sms-attributes-custom-value-round-trip."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "sms-attributes-custom-value-round-trip"
GROUP = "server-side"
SERVICES = ["sns"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:sns-sms-attributes")
def run(ctx) -> None:
    """A custom SMS account attribute value set via SetSMSAttributes is
    reflected exactly by a subsequent GetSMSAttributes call."""
    sns = ctx.client("sns")

    before = sns.get_sms_attributes()["attributes"]
    original_value = before.get("DefaultSenderID")

    def _restore():
        sns.set_sms_attributes(attributes={"DefaultSenderID": original_value or ""})

    ctx.on_cleanup(_restore)

    # DefaultSenderID must be alphanumeric and at most 11 characters
    new_value = ("S2R" + uuid.uuid4().hex.upper())[:11]
    sns.set_sms_attributes(attributes={"DefaultSenderID": new_value})

    after = sns.get_sms_attributes()["attributes"]
    assert after.get("DefaultSenderID") == new_value, (
        f"expected DefaultSenderID {new_value!r} to round-trip through "
        f"GetSMSAttributes, got {after.get('DefaultSenderID')!r}"
    )

    unrelated_before = {k: v for k, v in before.items() if k != "DefaultSenderID"}
    unrelated_after = {k: v for k, v in after.items() if k != "DefaultSenderID"}
    assert unrelated_after == unrelated_before, (
        f"SetSMSAttributes with only DefaultSenderID must not disturb other "
        f"account attributes: before={unrelated_before!r} after={unrelated_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
