"""image-task-and-fpga-error-semantics."""
from __future__ import annotations

from botocore.exceptions import ClientError, ParamValidationError

from behavioral_harness import tags


def _probe_errors(probes):
    """Assert a batch of zero-arg calls all fail with an expected error code.

    *probes* is a list of ``(label, fn, acceptable_codes)``. Every mismatch is
    collected rather than raising on the first. A local ``ParamValidationError``
    is itself a mismatch: it means the request never left the SDK, so it cannot
    exercise the server-side semantics this check exists to pin. Returns
    ``problems``.
    """
    problems = []
    for label, fn, expected in probes:
        try:
            fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in expected:
                problems.append(f"{label}: expected {sorted(expected)}, got {code}")
        except ParamValidationError as exc:
            problems.append(f"{label}: PARAM VALIDATION (request never reached AWS): {exc}")
        else:
            problems.append(f"{label}: expected {sorted(expected)} but the call SUCCEEDED")
    return problems


# Well-formed but nonexistent resource ids (17 hex chars after the prefix), so
# probes exercise NotFound semantics rather than id-format rejection.
_ABSENT = {
    "ami": "ami-0123456789abcdef0",
    "afi": "afi-0123456789abcdef0",
}

CHECK = "image-task-and-fpga-error-semantics"
GROUP = 'error-semantics'
SERVICES = ['ec2']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AMI store/restore and FPGA image operations must reject unknown ids."""
    ec2 = ctx.client("ec2")
    a = _ABSENT
    # Empirical: these operations reject the id on FORMAT grounds (".Malformed")
    # rather than reporting NotFound, even for a well-formed 17-hex-char id.
    problems = _probe_errors([
        (
            "create_store_image_task",
            lambda: ec2.create_store_image_task(
                ImageId=a["ami"], Bucket="sim2real-behav-no-such-bucket-xyz"
            ),
            ("InvalidAMIID.Malformed",),
        ),
        (
            "delete_fpga_image",
            lambda: ec2.delete_fpga_image(FpgaImageId=a["afi"]),
            ("InvalidFpgaImageID.Malformed",),
        ),
        (
            "deregister_image",
            lambda: ec2.deregister_image(ImageId=a["ami"]),
            ("InvalidAMIID.Malformed",),
        ),
    ])
    assert not problems, "unexpected image/FPGA error semantics:\n" + "\n".join(problems)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
