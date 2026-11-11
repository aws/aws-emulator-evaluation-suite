"""copy-fpga-image-invalid-source-region-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "copy-fpga-image-invalid-source-region-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CopyFpgaImage with SourceRegion eu-fake-9 is refused with InvalidParameterValue "Region name '<region>' is
    invalid.", while the same unknown AFI id with a valid region gets InvalidFpgaImageID.NotFound
    "Image ID '<id>' not found.".
    """
    ec2 = ctx.client("ec2")

    owned_afis = ec2.describe_fpga_images(Owners=["self"]).get("FpgaImages", [])
    if not owned_afis:
        bogus_afi_id = "afi-01234567"
        # Deliberately-invalid region string: the SUBJECT of this negative,
        # not a region-pinned resource literal.
        bogus_region = "eu-fake-9"

        region_code, region_message = _error_detail(
            lambda: ec2.copy_fpga_image(
                SourceFpgaImageId=bogus_afi_id, SourceRegion=bogus_region
            )
        )
        assert region_code == "InvalidParameterValue", (
            f"expected InvalidParameterValue for a bogus SourceRegion, got {region_code!r} ({region_message})"
        )
        assert region_message == f"Region name '{bogus_region}' is invalid.", f"unexpected error message {region_message!r}"

        # Positive control: the same AFI id with a valid region gets a different error (the image is not
        # found), so the region check does not refuse every request.
        notfound_code, notfound_message = _error_detail(
            lambda: ec2.copy_fpga_image(
                SourceFpgaImageId=bogus_afi_id, SourceRegion=ctx.region
            )
        )
        assert notfound_code != region_code, (
            "CopyFpgaImage returned the SAME error code for a garbage region "
            f"and for a valid region ({notfound_code!r}); it is not actually "
            "distinguishing a region-validation failure from an image lookup failure"
        )
        assert notfound_code == "InvalidFpgaImageID.NotFound", (
            f"expected InvalidFpgaImageID.NotFound once the region is valid, got {notfound_code!r}"
        )
        assert notfound_message == f"Image ID '{bogus_afi_id}' not found.", f"unexpected error message {notfound_message!r}"
        return

    # An owned AFI exists (rare) -- run the real, deep version of the check.
    afi_id = owned_afis[0]["FpgaImageId"]
    bogus_region = "eu-fake-9"
    code, message = _error_detail(
        lambda: ec2.copy_fpga_image(SourceFpgaImageId=afi_id, SourceRegion=bogus_region)
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    assert message == f"Region name '{bogus_region}' is invalid.", f"unexpected error message {message!r}"

    before_ids = {img["FpgaImageId"] for img in ec2.describe_fpga_images(Owners=["self"]).get("FpgaImages", [])}
    assert before_ids == {a["FpgaImageId"] for a in owned_afis}, "rejected copy must not create a new AFI"

    result = ec2.copy_fpga_image(SourceFpgaImageId=afi_id, SourceRegion=ctx.region)
    new_afi_id = result["FpgaImageId"]
    ctx.on_cleanup(lambda: ec2.delete_fpga_image(FpgaImageId=new_afi_id))
    assert new_afi_id and new_afi_id != afi_id


def _error_detail(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
