"""capacity-reservation-family-error-semantics."""
from __future__ import annotations

from botocore.exceptions import ClientError


from behavioral_harness import tags


def _probe_errors(client, probes):
    """Assert a batch of operations all fail with an expected error code.

    *probes* is a list of ``(client_method, kwargs, acceptable_codes)``. Every
    mismatch is collected rather than raising on the first, and operations the
    installed botocore does not know about are reported as skipped. Returns
    ``(problems, skipped)``.

    None of ``InstancePlatform``, ``AllocationStrategy`` or the capacity-reservation
    id fields carry a ``min``/``max``/``pattern`` constraint in the EC2 model, so
    botocore's local validator never intercepts these probes before they reach the
    service -- there is deliberately no ``ParamValidationError`` branch here. Catching
    one and counting it as a rejection would grade every target identically without
    ever asking it anything (it never leaves the SDK).
    """
    problems = []
    skipped = []
    for method, kwargs, expected in probes:
        fn = getattr(client, method, None)
        if fn is None:
            skipped.append(method)
            continue
        try:
            fn(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in expected:
                problems.append(f"{method}: expected {sorted(expected)}, got {code}")
        else:
            problems.append(f"{method}: expected {sorted(expected)} but the call SUCCEEDED")
    return problems, skipped


def _first_az(ec2):
    """The first AZ currently 'available' in this region."""
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        ).get("AvailabilityZones", [])
    ]
    if not azs:
        raise AssertionError("no available AZs in region")
    return azs[0]


# Well-formed but nonexistent resource ids (17 hex chars after the prefix), so
# probes exercise NotFound semantics rather than id-format rejection.
_ABSENT = {
    "capacity_res": "cr-0123456789abcdef0",
}

CHECK = "capacity-reservation-family-error-semantics"
GROUP = 'error-semantics'
SERVICES = ['ec2']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Capacity reservation operations must reject unknown reservations and bad params."""
    ec2 = ctx.client("ec2")
    a = _ABSENT
    az = _first_az(ec2)

    problems, _ = _probe_errors(ec2, [
        (
            "create_capacity_reservation",
            {
                "InstanceType": "t3.micro",
                "InstancePlatform": "Not A Real Platform",
                "InstanceCount": 1,
                "AvailabilityZone": az,
            },
            ("InvalidParameterValue",),
        ),
        (
            "create_capacity_reservation_by_splitting",
            {"SourceCapacityReservationId": a["capacity_res"], "InstanceCount": 1},
            (
                "InvalidCapacityReservationId.NotFound",
                "InvalidCapacityReservation.StateTransition",
            ),
        ),
        (
            "create_capacity_reservation_fleet",
            {
                "TotalTargetCapacity": 1,
                "InstanceTypeSpecifications": [
                    {
                        "InstanceType": "t3.micro",
                        "InstancePlatform": "Linux/UNIX",
                        "Weight": 1.0,
                        "AvailabilityZone": az,
                    }
                ],
                "AllocationStrategy": "not-a-strategy",
            },
            ("InvalidParameterValue", "MissingParameter"),
        ),
    ])
    assert not problems, (
        "unexpected capacity-reservation error semantics:\n" + "\n".join(problems)
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
