"""tag-nonexistent-mfa-device-rejected-not-silently-accepted."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-nonexistent-mfa-device-rejected-not-silently-accepted"
GROUP = "overly-permissive"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagMFADevice on a serial number for a device that was never created must fail with
    NoSuchEntity rather than silently succeeding; a real device in the same account can
    still be tagged successfully."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    device_name = ctx.unique_name("sim2real-mfa-tag-")
    real_serial = iam.create_virtual_mfa_device(VirtualMFADeviceName=device_name)["VirtualMFADevice"][
        "SerialNumber"
    ]
    ctx.on_cleanup(lambda: iam.delete_virtual_mfa_device(SerialNumber=real_serial))

    # Positive control: tagging a device that actually exists succeeds and is visible.
    iam.tag_mfa_device(SerialNumber=real_serial, Tags=[{"Key": "sim2real-env", "Value": "test"}])
    tags = iam.list_mfa_device_tags(SerialNumber=real_serial)["Tags"]
    assert {"Key": "sim2real-env", "Value": "test"} in tags

    # Negative: a serial number for a device that was never created.
    fake_name = ctx.unique_name("sim2real-mfa-never-created-")
    fake_serial = f"arn:aws:iam::{account_id}:mfa/{fake_name}"
    code, message = _error(
        lambda: iam.tag_mfa_device(SerialNumber=fake_serial, Tags=[{"Key": "sim2real-env", "Value": "test"}])
    )
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"MFA Device with serial number {fake_serial} does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no ghost device was created as a side effect of the tag call --
    # any lookup against that serial still reports it as unknown.
    lookup_code, lookup_message = _error(lambda: iam.list_mfa_device_tags(SerialNumber=fake_serial))
    assert lookup_code == "NoSuchEntity", f"expected NoSuchEntity on lookup, got {lookup_code}"
    expected = f"MFA Device with serial number {fake_serial} does not exist."
    assert lookup_message == expected, f"expected message {expected!r}, got {lookup_message!r}"


def _error(fn):
    """Call fn(); return botocore's (Error.Code, Error.Message). An unexpected SUCCESS raises, because a
    target that silently accepts a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
