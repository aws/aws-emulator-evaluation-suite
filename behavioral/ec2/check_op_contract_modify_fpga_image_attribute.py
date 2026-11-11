"""op-contract-modify-fpga-image-attribute."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-modify-fpga-image-attribute"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyFpgaImageAttribute rejects an unknown AFI id with InvalidFpgaImageID.NotFound and its exact
    message, and, when a foreign-owned AFI is discoverable, rejects it with AuthFailure."""
    ec2 = ctx.client("ec2")

    # A fresh test account owns no FPGA images at all -- creating one requires a
    # purchased FPGA hardware design -- so the self-owned collection must be empty, not
    # merely present.
    own = ec2.describe_fpga_images(Owners=["self"])["FpgaImages"]
    assert own == [], f"expected no self-owned FPGA images, got {own!r}"

    code_not_found, msg_not_found = _error(
        lambda: ec2.modify_fpga_image_attribute(
            FpgaImageId="afi-00000000000000000",
            Attribute="description",
            Description="sim2real-behav-test",
        )
    )
    assert code_not_found == "InvalidFpgaImageID.NotFound", (
        f"expected InvalidFpgaImageID.NotFound, got {code_not_found}"
    )
    expected_not_found = "The fpga-image ID 'afi-00000000000000000' does not exist"
    assert msg_not_found == expected_not_found, f"expected message {expected_not_found!r}, got {msg_not_found!r}"

    # Best-effort discovery of a foreign-owned AFI: AWS keeps no public AFI catalog, so both owner
    # filters usually return nothing and this branch is skipped; no AFI id is hard-coded.
    foreign_candidates = ec2.describe_fpga_images(
        Owners=["amazon", "aws-marketplace"], MaxResults=10
    )["FpgaImages"]
    if foreign_candidates:
        foreign_afi = foreign_candidates[0]["FpgaImageId"]
        code_forbidden, _ = _error(
            lambda: ec2.modify_fpga_image_attribute(
                FpgaImageId=foreign_afi,
                Attribute="description",
                Description="sim2real-behav-test",
            )
        )
        # The message is not asserted: no foreign-owned AFI is normally discoverable, so only the
        # code is pinned.
        assert code_forbidden == "AuthFailure", f"expected AuthFailure, got {code_forbidden}"


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses fails loudly instead of as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
