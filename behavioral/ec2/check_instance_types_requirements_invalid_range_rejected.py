"""instance-types-requirements-invalid-range-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "instance-types-requirements-invalid-range-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetInstanceTypesFromInstanceRequirements rejects a VCpuCount range whose
    Min exceeds its Max instead of silently returning zero/garbage results."""
    ec2 = ctx.client("ec2")

    # Positive control: the identical call shape with a valid (Min <= Max) range
    # succeeds, so the rejection below is attributable to the inverted bound and
    # not to this account/credential pair being unable to call the API at all.
    control = ec2.get_instance_types_from_instance_requirements(
        ArchitectureTypes=["x86_64"],
        VirtualizationTypes=["hvm"],
        InstanceRequirements={
            "VCpuCount": {"Min": 1, "Max": 96},
            "MemoryMiB": {"Min": 512, "Max": 4096},
        },
    )
    assert control["InstanceTypes"], "positive control (Min=1, Max=96) matched no instance types"

    code, message = _error(
        lambda: ec2.get_instance_types_from_instance_requirements(
            ArchitectureTypes=["x86_64"],
            VirtualizationTypes=["hvm"],
            InstanceRequirements={
                "VCpuCount": {"Min": 96, "Max": 1},
                "MemoryMiB": {"Min": 512, "Max": 4096},
            },
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}"
    expected = "vCpuCount.Min must be less than or equal to vCpuCount.Max."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises
    AssertionError: a target that accepts what AWS refuses fails loudly here."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
