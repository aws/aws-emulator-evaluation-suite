"""describe-fpga-image-attribute-reflects-load-permissions."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-fpga-image-attribute-reflects-load-permissions"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """The account owns no AFI and DescribeFpgaImages lists a non-empty Amazon/Marketplace catalog, but
    DescribeFpgaImageAttribute answers InvalidFpgaImageID.NotFound for every catalog AFI, so no AFI can be
    copied or inspected.
    """
    ec2 = ctx.client("ec2")

    # Positive control (own account): the read-side call succeeds and the caller owns nothing --
    # an emulator that fabricates self-owned images, or that errors on this call, fails right here.
    self_owned = ec2.describe_fpga_images(Owners=["self"])["FpgaImages"]
    assert self_owned == [], "a fresh test account should not own any FPGA images"

    # Positive control (catalog): DescribeFpgaImages itself is healthy and non-empty for the
    # Amazon/Marketplace catalog -- rules out "the whole read side is broken or denied" as the
    # explanation for every attribute-probe below coming back NotFound.
    catalog = (
        ec2.describe_fpga_images(Owners=["amazon"]).get("FpgaImages", [])
        + ec2.describe_fpga_images(Owners=["aws-marketplace"]).get("FpgaImages", [])
    )
    assert catalog, "expected DescribeFpgaImages to list at least one Amazon/Marketplace AFI"

    # Every catalogued id must be independently confirmed dead: DescribeFpgaImageAttribute can
    # neither resolve nor leak the existence of any of them under any other code.
    resolved = {}
    wrong_code = {}
    for img in catalog:
        fid = img["FpgaImageId"]
        try:
            ec2.describe_fpga_image_attribute(FpgaImageId=fid, Attribute="loadPermission")
            resolved[fid] = "SUCCESS"
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "InvalidFpgaImageID.NotFound":
                wrong_code[fid] = code

    assert not resolved, (
        f"expected every catalogued AFI to be unresolvable, but DescribeFpgaImageAttribute "
        f"actually described {resolved!r} -- a real source AFI now exists and this check "
        "should be rewritten to copy it and compare load permissions"
    )
    assert not wrong_code, (
        f"expected InvalidFpgaImageID.NotFound for every catalogued-but-dead AFI, got {wrong_code!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
