"""op-contract-modify-reserved-instances-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-modify-reserved-instances-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyReservedInstances against one unknown Reserved Instance id answers three different target
    configurations with three different codes and exact messages: MissingParameter (no scope),
    InvalidParameterValue (malformed AvailabilityZone) and InvalidInput (the id is not found)."""
    ec2 = ctx.client("ec2")
    zone = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-type", "Values": ["availability-zone"]}]
    )["AvailabilityZones"][0]["ZoneName"]

    active = ec2.describe_reserved_instances(
        Filters=[{"Name": "state", "Values": ["active"]}]
    )["ReservedInstances"]
    assert isinstance(active, list)  # sanity: the call itself is reachable and well-formed

    bogus_id = "1a2b3c4d-1234-5678-9abc-1234567890ab"

    # Positive-control leg 1: omitting both AvailabilityZone and Platform is rejected
    # server-side as a missing scope axis -- MissingParameter -- before the id is ever looked up.
    code, message = _error(
        lambda: ec2.modify_reserved_instances(
            ReservedInstancesIds=[bogus_id],
            TargetConfigurations=[{"InstanceCount": 1, "InstanceType": "t3.micro"}],
        )
    )
    assert code == "MissingParameter", f"expected MissingParameter for a scope-less target configuration, got {code}"
    assert message == "The request must contain the parameter  AvailabilityZone", message

    # Positive-control leg 2: a syntactically bogus AvailabilityZone is rejected server-side as a
    # malformed value -- InvalidParameterValue -- distinct from leg 1 and from the id-ambiguity
    # case below, proving the service actually validates the AZ's format rather than ignoring it.
    code, message = _error(
        lambda: ec2.modify_reserved_instances(
            ReservedInstancesIds=[bogus_id],
            TargetConfigurations=[
                {
                    "AvailabilityZone": "not-a-real-az",
                    "InstanceCount": 1,
                    "InstanceType": "t3.micro",
                }
            ],
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue for a malformed AvailabilityZone, got {code}"
    assert message == "Invalid value 'not-a-real-az' for AvailabilityZone.", message

    # The contract under test: with a well-formed single-axis target configuration (a real
    # AvailabilityZone, not a Platform, plus InstanceType), real AWS still validates whether the
    # requested configuration is coherent for a Reserved Instance (region-scoped vs. zone-scoped)
    # before it ever resolves ReservedInstancesIds against the account's inventory. Since no such
    # Reserved Instance can exist for a bogus id, AWS can't tell whether the AvailabilityZone axis
    # is applicable and rejects the call with the generic "InvalidInput" up front -- a *third*,
    # again-distinct code from the two legs above, so this is not the same blanket rejection.
    code, message = _error(
        lambda: ec2.modify_reserved_instances(
            ReservedInstancesIds=[bogus_id],
            TargetConfigurations=[
                {
                    "AvailabilityZone": zone,
                    "InstanceCount": 1,
                    "InstanceType": "t3.micro",
                }
            ],
        )
    )
    assert code == "InvalidInput", f"expected InvalidInput for a well-formed but scope-ambiguous bogus id, got {code}"
    assert message == f" Invalid value for 'reservedInstancesIds'. Reserved Instance {bogus_id} is not found.", message


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
