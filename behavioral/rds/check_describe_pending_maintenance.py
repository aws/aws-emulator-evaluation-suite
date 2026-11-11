"""describe-pending-maintenance."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "describe-pending-maintenance"
GROUP = 'maintenance'
SERVICES = ['rds']

ERR_INVALID_FILTER = "InvalidParameterValue"

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribePendingMaintenanceActions returns a well-formed (possibly empty) response,
    and rejects a Filters entry naming a filter that is not in its documented set
    (db-cluster-id, db-instance-id) rather than silently ignoring it."""
    rds = ctx.client("rds")

    resp = rds.describe_pending_maintenance_actions()
    assert "PendingMaintenanceActions" in resp, f"missing key in response: {resp!r}"
    assert isinstance(resp["PendingMaintenanceActions"], list), (
        f"expected a list, got {resp['PendingMaintenanceActions']!r}"
    )

    code = message = None
    bogus_filter = "sim2real-not-a-real-filter-name"
    try:
        rds.describe_pending_maintenance_actions(
            Filters=[{"Name": bogus_filter, "Values": ["x"]}]
        )
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        message = e.response.get("Error", {}).get("Message")
    assert code == ERR_INVALID_FILTER, (
        f"expected {ERR_INVALID_FILTER!r} for an unrecognized Filters name, got {code!r}"
    )
    assert message == f"Unrecognized filter name: {bogus_filter}", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
