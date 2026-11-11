"""op-contract-describeFpgaImages."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeFpgaImages"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeFpgaImages returns the well-formed collection shape scoped by owner, accepts a
    real FpgaImageIds lookup, and rejects a malformed/nonexistent AFI ID."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_fpga_images(Owners=["self"])
    assert "FpgaImages" in resp, f"expected a FpgaImages key, got keys {sorted(resp)!r}"
    assert isinstance(resp["FpgaImages"], list), f"expected a list, got {type(resp['FpgaImages'])!r}"
    assert resp["FpgaImages"] == [], f"expected no self-owned AFIs, got {resp['FpgaImages']!r}"

    # A syntactically valid filter must still be accepted even though it matches nothing of ours.
    filtered = ec2.describe_fpga_images(
        Owners=["self"], Filters=[{"Name": "state", "Values": ["available"]}]
    )
    assert filtered["FpgaImages"] == [], (
        f"expected no self-owned AFIs under a valid filter, got {filtered['FpgaImages']!r}"
    )

    # --- positive control: FpgaImageIds is a specific-resource lookup, so before trusting the
    # rejection below we must first show that a REAL id is accepted through that same param --
    # otherwise a target that rejects every FpgaImageIds lookup would also pass. AFIs require FPGA
    # (F1) design artifacts to create and cannot be provisioned as test fixtures. Not every AFI
    # reported as "public" is actually describable (some are stale or region-restricted), so try a
    # few. ---
    candidates = ec2.describe_fpga_images(Owners=["amazon", "aws-marketplace"])["FpgaImages"]
    public = [img for img in candidates if img.get("Public")]
    if not public:
        raise AssertionError("no public FPGA image (AFI) available in this account/region")

    real_id = None
    for candidate in public:
        try:
            by_id = ec2.describe_fpga_images(FpgaImageIds=[candidate["FpgaImageId"]])
        except ClientError as exc:
            if exc.response["Error"]["Code"].endswith("NotFound"):
                continue
            raise
        real_id = candidate["FpgaImageId"]
        break
    if real_id is None:
        raise AssertionError("no public FPGA image (AFI) in this account/region is actually describable")

    returned_ids = [img["FpgaImageId"] for img in by_id["FpgaImages"]]
    assert returned_ids == [real_id], f"expected exactly [{real_id!r}], got {returned_ids!r}"

    # --- error boundary: a well-formed but nonexistent AFI ID must be rejected -- unlike some
    # other Describe* operations, DescribeFpgaImages treats FpgaImageIds as a specific-resource
    # lookup and raises for an unrecognized ID rather than silently matching nothing. The positive
    # control above rules out "rejects every FpgaImageIds lookup" as the explanation. ---
    bogus_id = "afi-0123456789abcdef0"

    def _call():
        ec2.describe_fpga_images(FpgaImageIds=[bogus_id])

    code, message = _error(_call)
    assert code == "InvalidFpgaImageID.Malformed", f"expected InvalidFpgaImageID.Malformed, got {code!r}"
    expected = f"Image ID '{bogus_id}' is invalid."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Return fn()'s (code, message); a success raises, never reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
