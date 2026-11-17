"""tag-mfa-device-reserved-prefix-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-mfa-device-reserved-prefix-rejected"
GROUP = "overly-permissive"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagMFADevice on a virtual MFA device accepts an ordinary tag key, then refuses a batch
    that mixes one with the AWS-reserved 'aws:' prefix, applying none of it.

    Reference: https://docs.aws.amazon.com/IAM/latest/APIReference/API_TagMFADevice.html
    """
    iam = ctx.client("iam")
    device_name = ctx.unique_name("sim2real-behav-vmfa-")
    serial = iam.create_virtual_mfa_device(VirtualMFADeviceName=device_name)["VirtualMFADevice"][
        "SerialNumber"
    ]
    ctx.on_cleanup(lambda: iam.delete_virtual_mfa_device(SerialNumber=serial))

    iam.tag_mfa_device(SerialNumber=serial, Tags=[{"Key": "team", "Value": "payments"}])
    tags_after_first = {t["Key"]: t["Value"] for t in iam.list_mfa_device_tags(SerialNumber=serial)["Tags"]}
    assert tags_after_first == {"team": "payments"}, (
        f"expected the device to carry only team=payments after the first TagMFADevice call, "
        f"got {tags_after_first!r}"
    )

    mixed_batch = [
        {"Key": "stage", "Value": "canary"},
        {"Key": "aws:internal-marker", "Value": "blocked"},
    ]
    try:
        iam.tag_mfa_device(SerialNumber=serial, Tags=mixed_batch)
    except ClientError as exc:
        error = exc.response["Error"]
        assert error["Code"] == "InvalidInput", f"expected InvalidInput, got {error['Code']!r}"
        assert error["Message"] == "Tag keys beginning with aws: are reserved for system use.", (
            f"unexpected refusal message: {error['Message']!r}"
        )
    else:
        raise AssertionError(
            "TagMFADevice accepted a batch containing an 'aws:'-prefixed key, but real AWS "
            "refuses the entire call"
        )

    tags_after_rejection = {
        t["Key"]: t["Value"] for t in iam.list_mfa_device_tags(SerialNumber=serial)["Tags"]
    }
    assert tags_after_rejection == tags_after_first, (
        f"a rejected TagMFADevice call must leave the device's tags untouched: "
        f"{tags_after_first!r} -> {tags_after_rejection!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
