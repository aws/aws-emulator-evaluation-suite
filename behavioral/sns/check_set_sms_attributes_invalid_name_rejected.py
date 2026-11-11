"""set-sms-attributes-invalid-name-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-sms-attributes-invalid-name-rejected"
GROUP = 'overly-permissive'
SERVICES = ['sns']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:sns-sms-attributes")
def run(ctx) -> None:
    """SetSMSAttributes must reject unknown attribute names instead of storing them."""
    sns = ctx.client("sns")

    original = sns.get_sms_attributes(attributes=["DefaultSenderID"])["attributes"]
    original_value = original.get("DefaultSenderID")
    ctx.on_cleanup(
        lambda: sns.set_sms_attributes(attributes={"DefaultSenderID": original_value or ""})
    )

    # Positive control: a genuinely valid attribute name must be accepted and
    # reflected, proving the account/credentials are healthy for
    # SetSMSAttributes before the negative below is meaningful.
    control_value = ("S2R" + uuid.uuid4().hex.upper())[:11]
    sns.set_sms_attributes(attributes={"DefaultSenderID": control_value})
    reflected = sns.get_sms_attributes(attributes=["DefaultSenderID"])["attributes"]
    assert reflected.get("DefaultSenderID") == control_value, (
        f"positive control failed: expected DefaultSenderID={control_value!r}, got {reflected}"
    )

    try:
        sns.set_sms_attributes(attributes={"NotARealSmsAttribute": "some-value"})
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(
            "SetSMSAttributes with an unknown attribute name was expected to be rejected, "
            "but it SUCCEEDED"
        )
    assert code == "InvalidParameter", (
        f"expected InvalidParameter for an unknown SMS attribute name, got {code}"
    )
    assert message == 'NotARealSmsAttribute is not a valid attribute', (
        f"expected the exact message 'NotARealSmsAttribute is not a valid attribute', got {message!r}"
    )

    attrs = sns.get_sms_attributes()["attributes"]
    assert "NotARealSmsAttribute" not in attrs, (
        f"rejected SetSMSAttributes must not persist the attribute: {attrs}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
