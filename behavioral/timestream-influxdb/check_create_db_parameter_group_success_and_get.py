"""create-db-parameter-group-success-and-get."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-db-parameter-group-success-and-get"
GROUP = "control-plane"
SERVICES = ["timestream-influxdb"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDbParameterGroup returns the created group's identity and metadata, and
    GetDbParameterGroup reflects the same values afterwards."""
    influx = ctx.client("timestream-influxdb")
    name = ctx.unique_name("sim2real-pg-")
    description = "sim2real behavioral check parameter group"

    created = influx.create_db_parameter_group(
        name=name, description=description, tags={"env": "sim2real"}
    )
    pg_id = created["id"]
    assert created["name"] == name, f"expected created name {name!r}, got {created['name']!r}"
    assert created["description"] == description, (
        f"expected created description {description!r}, got {created['description']!r}"
    )
    assert created["arn"].endswith(f"db-parameter-group/{pg_id}"), (
        f"expected arn to end with 'db-parameter-group/{pg_id}', got {created['arn']!r}"
    )

    fetched = influx.get_db_parameter_group(identifier=pg_id)
    assert fetched["id"] == pg_id, f"expected fetched id {pg_id!r}, got {fetched['id']!r}"
    assert fetched["name"] == name, f"expected fetched name {name!r}, got {fetched['name']!r}"
    assert fetched["description"] == description, (
        f"expected fetched description {description!r}, got {fetched['description']!r}"
    )
    # Note: Timestream for InfluxDB has no DeleteDbParameterGroup API, so this
    # lightweight metadata object is intentionally left in the account (no cleanup call
    # is possible); ctx.unique_name keeps it from colliding with other runs.


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
