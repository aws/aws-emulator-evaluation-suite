"""get-parameters-resolves-two-ami-parameters-and-reports-the-unknown-one-invalid."""
# Read-only, AWS-owned data: nothing is created, so there is nothing to tear down.
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "get-parameters-resolves-two-ami-parameters-and-reports-the-unknown-one-invalid"
GROUP = "catalog"
SERVICES = ["ec2", "ssm"]

#: AWS-owned public parameters (contract/aws-owned: `/aws/service/*`).
_PATH = "/aws/service/ami-amazon-linux-latest"
AL2023_DEFAULT = f"{_PATH}/al2023-ami-kernel-default-x86_64"
AL2023_MINIMAL = f"{_PATH}/al2023-ami-minimal-kernel-default-x86_64"
_AMI_ID = re.compile(r"^ami-[0-9a-f]{8,17}$")


@tags("axis:happy-path", "cap:c5", "plane:control")
def run(ctx) -> None:
    """One GetParameters call resolves the AL2023 default and minimal x86_64 parameters to two
    different available Amazon images, whose names tell minimal from default, and reports the
    unknown name beside them in InvalidParameters."""
    ssm, ec2 = ctx.client("ssm"), ctx.client("ec2")
    unknown = f"{_PATH}/{ctx.unique_name('sim2real-absent-')}"

    resp = ssm.get_parameters(Names=[AL2023_DEFAULT, unknown, AL2023_MINIMAL])
    assert resp.get("InvalidParameters") == [unknown], (
        f"GetParameters InvalidParameters: expected exactly the unknown name, got {resp.get('InvalidParameters')!r}"
    )
    values = {p.get("Name"): p.get("Value") for p in resp.get("Parameters") or []}
    assert sorted(values) == sorted([AL2023_DEFAULT, AL2023_MINIMAL]), (
        f"GetParameters Parameters: expected the two known names, got {sorted(values)!r}"
    )
    default_ami, minimal_ami = values[AL2023_DEFAULT], values[AL2023_MINIMAL]
    for name, ami in values.items():
        assert _AMI_ID.match(ami or ""), f"{name}: expected an ami id, got {ami!r}"
    assert default_ami != minimal_ami, f"default and minimal parameters resolved to one image {default_ami!r}"

    # Each batch value agrees with the single-name read.
    for name, ami in values.items():
        single = ssm.get_parameter(Name=name)["Parameter"]["Value"]
        assert single == ami, f"GetParameter {name} answered {single!r}, GetParameters {ami!r}"

    images = {i["ImageId"]: i for i in ec2.describe_images(ImageIds=[default_ami, minimal_ami]).get("Images", [])}
    assert sorted(images) == sorted([default_ami, minimal_ami]), (
        f"DescribeImages: expected both resolved images, got {sorted(images)!r}"
    )
    for ami, minimal in ((default_ami, False), (minimal_ami, True)):
        img = images[ami]
        got = (img.get("State"), img.get("Architecture"), img.get("ImageOwnerAlias"), img.get("Public"),
               img.get("Name", "").startswith("al2023-ami-minimal-"), img.get("Name", "").startswith("al2023-ami-"))
        want = ("available", "x86_64", "amazon", True, minimal, True)
        assert got == want, (
            f"image of the {'minimal' if minimal else 'default'} parameter (state, arch, owner alias, "
            f"public, minimal name, al2023 name): expected {want!r}, got {got!r} (name {img.get('Name')!r})"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
