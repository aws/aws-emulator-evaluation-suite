"""list-db-parameter-groups-includes-created-group."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-db-parameter-groups-includes-created-group"
GROUP = "control-plane"
SERVICES = ["timestream-influxdb"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created DB parameter group shows up in ListDbParameterGroups with matching
    id, name and ARN (paginating through results if necessary)."""
    influx = ctx.client("timestream-influxdb")
    name = ctx.unique_name("sim2real-pglist-")
    created = influx.create_db_parameter_group(name=name, description="listing check")

    found = _find_by_name(influx, name)
    assert found is not None, f"parameter group {name!r} not found via ListDbParameterGroups"
    assert found["id"] == created["id"], f"id mismatch: listed {found['id']!r} vs created {created['id']!r}"
    assert found["arn"] == created["arn"], f"arn mismatch: listed {found['arn']!r} vs created {created['arn']!r}"
    # Note: Timestream for InfluxDB has no DeleteDbParameterGroup API, so this
    # lightweight metadata object is intentionally left in the account (no cleanup call
    # is possible); ctx.unique_name keeps it from colliding with other runs.


def _find_by_name(influx, name):
    next_token = None
    for _ in range(20):
        kwargs = {"maxResults": 100}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = influx.list_db_parameter_groups(**kwargs)
        for item in resp.get("items", []):
            if item["name"] == name:
                return item
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
