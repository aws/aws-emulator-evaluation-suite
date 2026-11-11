"""mfa-device-tag-unicode-value-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "mfa-device-tag-unicode-value-preserved"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A multilingual non-ASCII tag value set via TagMFADevice reads back unchanged from
    ListMFADeviceTags."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-mfatag-")

    dev = iam.create_virtual_mfa_device(VirtualMFADeviceName=name)["VirtualMFADevice"]
    serial = dev["SerialNumber"]
    ctx.on_cleanup(lambda: iam.delete_virtual_mfa_device(SerialNumber=serial))

    # Tag values allow only Unicode letters, numbers and separators, so no symbols or emoji.
    unicode_value = "東京-café-Zürich-Москва"
    iam.tag_mfa_device(
        SerialNumber=serial, Tags=[{"Key": "sim2real-label", "Value": unicode_value}]
    )

    tags = iam.list_mfa_device_tags(SerialNumber=serial)["Tags"]
    matching = [t["Value"] for t in tags if t["Key"] == "sim2real-label"]
    assert matching == [unicode_value], f"expected {unicode_value!r}, got {matching!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
