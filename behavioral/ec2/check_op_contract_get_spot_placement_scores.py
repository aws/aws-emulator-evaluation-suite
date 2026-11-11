"""op-contract-get-spot-placement-scores."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-get-spot-placement-scores"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSpotPlacementScores returns a well-formed, bounded set of scored Regions for a
    real target capacity request; specifying both InstanceTypes and
    InstanceRequirementsWithMetadata (documented as mutually exclusive) is rejected."""
    ec2 = ctx.client("ec2")

    # success-path contract: each score is 1-10 and keyed to a real Region.
    resp = ec2.get_spot_placement_scores(
        InstanceTypes=["m5.large", "m5.xlarge", "c5.large"],
        TargetCapacity=1,
    )
    scores = resp["SpotPlacementScores"]
    assert len(scores) > 0, "expected at least one scored Region"
    for entry in scores:
        assert 1 <= entry["Score"] <= 10, f"score out of range: {entry!r}"
        assert entry["Region"], f"expected a non-empty Region, got {entry!r}"

    # error boundary: InstanceTypes and InstanceRequirementsWithMetadata are documented
    # as mutually exclusive -- specifying both is a distinct parameter-combination error,
    # not a NotFound or a silently-accepted request. Real AWS only enforces the mutex
    # once InstanceRequirementsWithMetadata is genuinely populated (confirmed against
    # real AWS: an empty {} is treated as "not specified" and the call silently
    # succeeds using InstanceTypes alone) -- so give it a fully-formed, valid value.
    code, message = _client_error(lambda: ec2.get_spot_placement_scores(
        InstanceTypes=["m5.large"],
        InstanceRequirementsWithMetadata={
            "ArchitectureTypes": ["x86_64"],
            "VirtualizationTypes": ["hvm"],
            "InstanceRequirements": {
                "VCpuCount": {"Min": 1, "Max": 2},
                "MemoryMiB": {"Min": 512, "Max": 2048},
            },
        },
        TargetCapacity=1,
    ))
    assert code == "InvalidParameterCombination", (
        f'expected error code "InvalidParameterCombination", got {code!r}'
    )
    expected_message = (
        "You can specify either InstanceTypes or InstanceRequirements, but not both. "
        "Remove either InstanceTypes or InstanceRequirements, and try again."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return its botocore error as (code, message). An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses is not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
