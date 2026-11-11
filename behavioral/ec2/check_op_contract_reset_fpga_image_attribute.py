"""op-contract-reset-fpga-image-attribute."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-reset-fpga-image-attribute"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ResetFpgaImageAttribute fails with InvalidFpgaImageID.Malformed for a malformed AFI id and with
    InvalidFpgaImageID.NotFound for a well-formed unassigned one, each with its exact message."""
    ec2 = ctx.client("ec2")

    malformed_code, malformed_message = _client_error(lambda: ec2.reset_fpga_image_attribute(
        FpgaImageId="not-an-afi-id", Attribute="loadPermission"))
    assert malformed_code == "InvalidFpgaImageID.Malformed", (
        f"expected InvalidFpgaImageID.Malformed, got {malformed_code}")
    expected_message = "The fpga-image ID 'not-an-afi-id' is malformed"
    assert malformed_message == expected_message, f"expected message {expected_message!r}, got {malformed_message!r}"

    # FPGA image IDs, like AMI IDs, are not eligible for the 17-hex-char
    # "long ID" format -- they stay at the original 8-hex-char length, so a
    # 17-char id like "afi-1234567890abcdef0" is rejected up front as
    # Malformed rather than reaching the existence check. Use a well-formed
    # (8-hex-char) but unassigned id instead.
    not_found_code, not_found_message = _client_error(lambda: ec2.reset_fpga_image_attribute(
        FpgaImageId="afi-12345678", Attribute="loadPermission"))
    assert not_found_code == "InvalidFpgaImageID.NotFound", (
        f"expected InvalidFpgaImageID.NotFound, got {not_found_code}")
    expected_message = "Image ID 'afi-12345678' not found."
    assert not_found_message == expected_message, f"expected message {expected_message!r}, got {not_found_message!r}"


def _client_error(fn):
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
