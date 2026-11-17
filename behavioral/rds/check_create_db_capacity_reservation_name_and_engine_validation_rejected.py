"""create-db-capacity-reservation-name-and-engine-validation-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-db-capacity-reservation-name-and-engine-validation-rejected"
GROUP = "capacity_reservations"
SERVICES = ["rds", "ec2"]

_SUPPORTED_ENGINES = (
    "aurora-mysql, aurora-postgresql, mysql, postgres, mariadb, sqlserver-ee, sqlserver-se, "
    "sqlserver-ex, sqlserver-web, sqlserver-dev-ee, sqlserver-dev-se, db2-ae, db2-se, db2-ce, "
    "oracle-ee, oracle-ee-cdb, oracle-se2, oracle-se2-cdb"
)


def _rejection(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDBCapacityReservation validates the reservation name and the engine's eligibility
    independently: a malformed name is refused before the engine is even considered, and a
    well-formed name with an engine Capacity Reservations does not support is refused separately.
    """
    rds = ctx.client("rds")
    ec2 = ctx.client("ec2")

    az = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    )[0]

    bad_name = "Sim2Real-Bad-Name"  # uppercase violates the lowercase-leading pattern
    err_name = _rejection(
        lambda: rds.create_db_capacity_reservation(
            DBCapacityReservationName=bad_name,
            DBInstanceClass="db.r7g.large",
            Engine="mysql",
            CapacityPerAvailabilityZone=1,
            AvailabilityZones=[az],
        )
    )
    assert err_name.get("Code") == "InvalidParameterValue", (
        f"malformed name {bad_name!r}: expected InvalidParameterValue, got {err_name}"
    )
    expected_name_msg = (
        f"1 validation error detected: Value '{bad_name}' at 'dBCapacityReservationName' failed "
        "to satisfy constraint: Member must satisfy regular expression pattern: "
        "[a-z](?:-?[a-z0-9]+){0,15}"
    )
    assert err_name.get("Message") == expected_name_msg, err_name.get("Message")

    good_name = ctx.unique_name("sim2real-dbcr-")
    err_engine = _rejection(
        lambda: rds.create_db_capacity_reservation(
            DBCapacityReservationName=good_name,
            DBInstanceClass="db.r7g.large",
            Engine="custom-oracle-ee",
            CapacityPerAvailabilityZone=1,
            AvailabilityZones=[az],
        )
    )
    assert err_engine.get("Code") == "InvalidParameterValue", (
        f"well-formed name with an engine Capacity Reservations does not support: "
        f"expected InvalidParameterValue, got {err_engine}"
    )
    expected_engine_msg = (
        "Unsupported engine type: custom-oracle-ee. Supported types are: "
        f"{_SUPPORTED_ENGINES}."
    )
    assert err_engine.get("Message") == expected_engine_msg, err_engine.get("Message")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
