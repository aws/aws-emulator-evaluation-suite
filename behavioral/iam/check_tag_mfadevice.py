"""tag-mfadevice."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-mfadevice"
GROUP = 'tags'
SERVICES = ['iam']


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagMFADevice persists tags on a virtual MFA device (keyed by its SerialNumber ARN) that
    ListMFADeviceTags then reflects exactly; tagging a nonexistent SerialNumber is rejected
    NoSuchEntity and leaves no ghost device behind."""
    iam = ctx.client("iam")
    device_name = ctx.unique_name("mfa-tag-")
    device = iam.create_virtual_mfa_device(VirtualMFADeviceName=device_name)["VirtualMFADevice"]
    serial = device["SerialNumber"]
    ctx.on_cleanup(lambda: iam.delete_virtual_mfa_device(SerialNumber=serial))

    iam.tag_mfa_device(SerialNumber=serial, Tags=[{"Key": "sim2real-k", "Value": "v1"}])
    ctx.on_cleanup(lambda: iam.untag_mfa_device(SerialNumber=serial, TagKeys=["sim2real-k"]))

    tags = iam.list_mfa_device_tags(SerialNumber=serial)["Tags"]
    assert {"Key": "sim2real-k", "Value": "v1"} in tags, f"tag missing: {tags}"

    account = ctx.client("sts").get_caller_identity()["Account"]
    fake_serial = f"arn:aws:iam::{account}:mfa/{ctx.unique_name('missing-')}"
    code, message = _error(
        lambda: iam.tag_mfa_device(SerialNumber=fake_serial, Tags=[{"Key": "k", "Value": "v"}])
    )
    assert code == "NoSuchEntity", f"expected NoSuchEntity for a nonexistent SerialNumber, got {code}"
    expected = f"MFA Device with serial number {fake_serial} does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    lookup_code, lookup_message = _error(lambda: iam.list_mfa_device_tags(SerialNumber=fake_serial))
    assert lookup_code == "NoSuchEntity", (
        f"tagging a nonexistent SerialNumber must not create a ghost device, got {lookup_code}"
    )
    expected = f"MFA Device with serial number {fake_serial} does not exist."
    assert lookup_message == expected, f"expected message {expected!r}, got {lookup_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
