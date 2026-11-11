"""untag-nonexistent-mfa-device-returns-nosuchentity."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-nonexistent-mfa-device-returns-nosuchentity"
GROUP = "overly-permissive"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagMFADevice on an unknown device ARN returns NoSuchEntity rather than a no-op
    success, while untagging a real, tagged device in the same account still succeeds."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    device_name = ctx.unique_name("sim2real-mfa-untag-")
    real_serial = iam.create_virtual_mfa_device(VirtualMFADeviceName=device_name)["VirtualMFADevice"][
        "SerialNumber"
    ]
    ctx.on_cleanup(lambda: iam.delete_virtual_mfa_device(SerialNumber=real_serial))
    iam.tag_mfa_device(SerialNumber=real_serial, Tags=[{"Key": "sim2real-env", "Value": "test"}])

    # Negative: an ARN for a device that was never created.
    fake_name = ctx.unique_name("sim2real-mfa-never-created-")
    fake_serial = f"arn:aws:iam::{account_id}:mfa/{fake_name}"
    code, message = _error(
        lambda: iam.untag_mfa_device(SerialNumber=fake_serial, TagKeys=["sim2real-env"])
    )
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"MFA Device with serial number {fake_serial} does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the tag on the real device (a distinct resource) was untouched by
    # the failed call against the fake serial.
    tags = iam.list_mfa_device_tags(SerialNumber=real_serial)["Tags"]
    assert {"Key": "sim2real-env", "Value": "test"} in tags, f"expected real device tag intact, got {tags}"

    # Positive control: untagging the real, existing device succeeds and removes the tag.
    iam.untag_mfa_device(SerialNumber=real_serial, TagKeys=["sim2real-env"])
    tags_after = iam.list_mfa_device_tags(SerialNumber=real_serial)["Tags"]
    assert tags_after == [], f"expected no tags remaining on real device, got {tags_after}"


def _error(fn):
    """Call fn(); return its error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
