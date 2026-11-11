"""create-db-parameter-group-duplicate-name-conflict-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-db-parameter-group-duplicate-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["timestream-influxdb"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateDbParameterGroup reusing an already-taken name is rejected with
    ConflictException and does not create a second group, while the original create
    (positive control) succeeded."""
    influx = ctx.client("timestream-influxdb")
    name = ctx.unique_name("sim2real-pgdup-")

    # Timestream for InfluxDB has no DeleteDbParameterGroup API, so both this group and
    # the rejected duplicate's target name are intentionally left in the account (no
    # cleanup call is possible); ctx.unique_name keeps it from colliding with other runs.
    first = influx.create_db_parameter_group(name=name, description="original")
    pg_id = first["id"]
    assert first["name"] == name, f"positive control: expected name {name!r}, got {first['name']!r}"

    err = _client_error(lambda: influx.create_db_parameter_group(name=name, description="duplicate"))
    assert err["Code"] == "ConflictException", f"expected ConflictException, got {err['Code']!r}"
    expected_message = (
        f"The DbParameterGroup with id [{pg_id}], name [{name}], customer [{ctx.account}] "
        "already exists"
    )
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # Effect absent: the original group's description was not overwritten by the
    # rejected duplicate, and there is still exactly one group with this name.
    unchanged = influx.get_db_parameter_group(identifier=pg_id)
    assert unchanged["description"] == "original", (
        f"rejected duplicate must not overwrite the original description: {unchanged['description']!r}"
    )

    matches = [g for g in _list_all_parameter_groups(influx) if g["name"] == name]
    assert len(matches) == 1, f"duplicate create must not have created a second group: {matches!r}"


def _client_error(fn):
    """Call fn(); return the botocore Error dict (Code and Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _list_all_parameter_groups(influx):
    items = []
    next_token = None
    for _ in range(20):
        kwargs = {"maxResults": 100}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = influx.list_db_parameter_groups(**kwargs)
        items.extend(resp.get("items", []))
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
