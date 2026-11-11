"""op-contract-delete-fpga-image-rejected."""
from __future__ import annotations

CHECK = "op-contract-delete-fpga-image-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]

from behavioral_harness import tags


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteFpgaImage with DryRun answers DryRunOperation; a 17-hex-digit ID fails with
    InvalidFpgaImageID.Malformed and an unassigned 8-hex-digit ID with InvalidFpgaImageID.NotFound,
    each with its exact message."""
    ec2 = ctx.client("ec2")
    fake_id = "afi-00000000000000000"

    dry_run_code, dry_run_message = _error(lambda: ec2.delete_fpga_image(FpgaImageId=fake_id, DryRun=True))
    assert dry_run_code == "DryRunOperation", f"expected DryRunOperation, got {dry_run_code!r}"
    assert dry_run_message == "Request would have succeeded, but DryRun flag is set.", dry_run_message

    # A 17-hex-char AFI id is malformed by FORMAT alone -- FPGA image ids never adopted the
    # long-ID format -- so this is rejected before the existence check ever runs.
    malformed_code, malformed_message = _error(lambda: ec2.delete_fpga_image(FpgaImageId=fake_id))
    assert malformed_code == "InvalidFpgaImageID.Malformed", (
        f"expected InvalidFpgaImageID.Malformed, got {malformed_code!r}")
    assert malformed_message == f"Image ID '{fake_id}' is invalid.", malformed_message

    # A well-formed (8-hex-char) but unassigned id reaches the existence check instead.
    unassigned_id = "afi-12345678"
    not_found_code, not_found_message = _error(lambda: ec2.delete_fpga_image(FpgaImageId=unassigned_id))
    assert not_found_code == "InvalidFpgaImageID.NotFound", (
        f"expected InvalidFpgaImageID.NotFound, got {not_found_code!r}")
    assert not_found_message == f"Image ID '{unassigned_id}' not found.", not_found_message


def _error(fn):
    """Call fn() and return the (code, message) of the error it raises. A call
    that SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must
    not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
