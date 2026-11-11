"""untag-mfadevice."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-mfadevice"
GROUP = 'tags'
SERVICES = ['iam']


def _error(fn):
    """Call fn(); return the botocore (Code, Message) of the ClientError it raises. An unexpected
    SUCCESS raises instead of returning a falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagMFADevice removes ONLY the named keys -- a second, untouched tag survives the call;
    untagging a nonexistent SerialNumber is rejected NoSuchEntity and leaves no ghost device
    that a later lookup can find."""
    iam = ctx.client("iam")
    device_name = ctx.unique_name("mfa-untag-")
    device = iam.create_virtual_mfa_device(VirtualMFADeviceName=device_name)["VirtualMFADevice"]
    serial = device["SerialNumber"]
    ctx.on_cleanup(lambda: iam.delete_virtual_mfa_device(SerialNumber=serial))
    iam.tag_mfa_device(
        SerialNumber=serial,
        Tags=[{"Key": "sim2real-keep", "Value": "v1"}, {"Key": "sim2real-drop", "Value": "v2"}],
    )

    iam.untag_mfa_device(SerialNumber=serial, TagKeys=["sim2real-drop"])
    tags = iam.list_mfa_device_tags(SerialNumber=serial)["Tags"]
    assert {"Key": "sim2real-keep", "Value": "v1"} in tags, f"untouched tag lost: {tags}"
    assert not any(t["Key"] == "sim2real-drop" for t in tags), f"targeted tag survived: {tags}"

    iam.untag_mfa_device(SerialNumber=serial, TagKeys=["sim2real-keep"])
    tags_after = iam.list_mfa_device_tags(SerialNumber=serial)["Tags"]
    assert tags_after == [], f"expected no tags remaining, got {tags_after}"

    account = ctx.client("sts").get_caller_identity()["Account"]
    fake_serial = f"arn:aws:iam::{account}:mfa/{ctx.unique_name('missing-')}"
    code, message = _error(lambda: iam.untag_mfa_device(SerialNumber=fake_serial, TagKeys=["k"]))
    assert code == "NoSuchEntity", f"expected NoSuchEntity for a nonexistent SerialNumber, got {code}"
    expected = f"MFA Device with serial number {fake_serial} does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    lookup_code, lookup_message = _error(lambda: iam.list_mfa_device_tags(SerialNumber=fake_serial))
    assert lookup_code == "NoSuchEntity", (
        f"expected the failed untag to leave no ghost device behind, got {lookup_code} on lookup"
    )
    expected_lookup = f"MFA Device with serial number {fake_serial} does not exist."
    assert lookup_message == expected_lookup, (
        f"expected lookup message {expected_lookup!r}, got {lookup_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
