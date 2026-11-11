"""mfa-device-tag-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "mfa-device-tag-lifecycle"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags attach to a virtual MFA device via TagMFADevice, are visible via
    ListMFADeviceTags, and a targeted key disappears after UntagMFADevice while
    an untouched key survives."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-mfa-")

    device = iam.create_virtual_mfa_device(VirtualMFADeviceName=name)["VirtualMFADevice"]
    serial = device["SerialNumber"]
    ctx.on_cleanup(lambda: iam.delete_virtual_mfa_device(SerialNumber=serial))

    _retry_until_success(
        lambda: iam.tag_mfa_device(
            SerialNumber=serial,
            Tags=[
                {"Key": "Environment", "Value": "sim2real-test"},
                {"Key": "Owner", "Value": "behavioral-suite"},
            ],
        )
    )

    tags = _tagmap(iam.list_mfa_device_tags(SerialNumber=serial)["Tags"])
    assert tags.get("Environment") == "sim2real-test", (
        f"expected Environment=sim2real-test after TagMFADevice, got {tags!r}"
    )
    assert tags.get("Owner") == "behavioral-suite", (
        f"expected Owner=behavioral-suite after TagMFADevice, got {tags!r}"
    )

    iam.untag_mfa_device(SerialNumber=serial, TagKeys=["Environment"])

    tags_after = _tagmap(iam.list_mfa_device_tags(SerialNumber=serial)["Tags"])
    assert "Environment" not in tags_after, (
        f"expected Environment removed by UntagMFADevice, still present in {tags_after!r}"
    )
    assert tags_after.get("Owner") == "behavioral-suite", (
        f"expected untouched Owner tag to survive UntagMFADevice, got {tags_after!r}"
    )


def _tagmap(tags):
    return {t["Key"]: t["Value"] for t in tags}


def _retry_until_success(fn, *, timeout_s=15.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "NoSuchEntityException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
