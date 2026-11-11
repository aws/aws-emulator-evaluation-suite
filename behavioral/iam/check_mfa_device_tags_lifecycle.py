"""mfa-device-tags-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "mfa-device-tags-lifecycle"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tagging a virtual MFA device makes tags visible via ListMFADeviceTags;
    untagging one key removes only that key, and untagging the rest leaves
    no tags behind."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-mfa-")
    created = iam.create_virtual_mfa_device(VirtualMFADeviceName=name)
    serial = created["VirtualMFADevice"]["SerialNumber"]
    ctx.on_cleanup(lambda: iam.delete_virtual_mfa_device(SerialNumber=serial))

    initial = iam.list_mfa_device_tags(SerialNumber=serial)["Tags"]
    assert initial == [], f"expected no tags before TagMFADevice, got {initial}"

    tags = [{"Key": "env", "Value": "test"}, {"Key": "owner", "Value": "identity-team"}]
    iam.tag_mfa_device(SerialNumber=serial, Tags=tags)

    listed = iam.list_mfa_device_tags(SerialNumber=serial)["Tags"]
    assert {(t["Key"], t["Value"]) for t in listed} == {(t["Key"], t["Value"]) for t in tags}, (
        f"expected tags {tags}, got {listed}"
    )

    iam.untag_mfa_device(SerialNumber=serial, TagKeys=["env"])
    after_partial = iam.list_mfa_device_tags(SerialNumber=serial)["Tags"]
    assert after_partial == [{"Key": "owner", "Value": "identity-team"}], (
        f"expected only the untouched 'owner' tag to survive removing 'env', got {after_partial}"
    )

    iam.untag_mfa_device(SerialNumber=serial, TagKeys=["owner"])
    after_full = iam.list_mfa_device_tags(SerialNumber=serial)["Tags"]
    assert after_full == [], f"expected tags removed after UntagMFADevice, got {after_full}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
