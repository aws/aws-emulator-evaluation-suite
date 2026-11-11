"""mfa-device-tagging."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "mfa-device-tagging"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagMFADevice adds tags visible via ListMFADeviceTags; UntagMFADevice removes them."""
    iam = ctx.client("iam")

    device_name = ctx.unique_name("sim2real-mfatag-")
    device = iam.create_virtual_mfa_device(VirtualMFADeviceName=device_name)["VirtualMFADevice"]
    serial = device["SerialNumber"]
    ctx.on_cleanup(lambda: iam.delete_virtual_mfa_device(SerialNumber=serial))

    before = iam.list_mfa_device_tags(SerialNumber=serial)["Tags"]
    assert before == [], f"expected no tags on fresh device, got {before}"

    iam.tag_mfa_device(SerialNumber=serial, Tags=[{"Key": "env", "Value": "behavioral"}, {"Key": "owner", "Value": "sim2real"}])
    tags = {t["Key"]: t["Value"] for t in iam.list_mfa_device_tags(SerialNumber=serial)["Tags"]}
    assert tags == {"env": "behavioral", "owner": "sim2real"}, f"unexpected tags after TagMFADevice: {tags}"

    iam.untag_mfa_device(SerialNumber=serial, TagKeys=["env"])
    tags_after = {t["Key"]: t["Value"] for t in iam.list_mfa_device_tags(SerialNumber=serial)["Tags"]}
    assert tags_after == {"owner": "sim2real"}, f"unexpected tags after partial UntagMFADevice: {tags_after}"

    iam.untag_mfa_device(SerialNumber=serial, TagKeys=["owner"])
    tags_final = iam.list_mfa_device_tags(SerialNumber=serial)["Tags"]
    assert tags_final == [], f"expected no tags after full untag, got {tags_final}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
