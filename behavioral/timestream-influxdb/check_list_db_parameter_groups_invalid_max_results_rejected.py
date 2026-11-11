"""list-db-parameter-groups-invalid-max-results-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-db-parameter-groups-invalid-max-results-rejected"
GROUP = "overly-permissive"
SERVICES = ["timestream-influxdb"]


_GROUP_COUNT = 2


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListDbParameterGroups refuses maxResults 101, above the documented maximum of 100, with ValidationException
    and its exact message; with two groups created, maxResults 1 returns one item and a nextToken, and maxResults
    100 lists both."""
    influx = ctx.client("timestream-influxdb")

    err = _client_error(lambda: influx.list_db_parameter_groups(maxResults=101))
    assert err["Code"] == "ValidationException", f"expected ValidationException, got {err['Code']!r}"
    expected_message = (
        "1 validation error(s) detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 100"
    )
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    names = [ctx.unique_name(f"sim2real-behav-dbpg-{i}-") for i in range(_GROUP_COUNT)]
    for name in names:
        influx.create_db_parameter_group(
            name=name, description="sim2real maxResults probe", tags={"env": "sim2real"}
        )

    # Positive control: an in-range maxResults succeeds and genuinely caps the page.
    capped = influx.list_db_parameter_groups(maxResults=1)
    assert len(capped["items"]) == 1, (
        f"maxResults=1 must return exactly 1 item when more are available; "
        f"got {len(capped['items'])}"
    )
    assert capped.get("nextToken") is not None, (
        f"more than 1 group exists (at least the {names!r} just created), so a maxResults=1 "
        f"page must carry a nextToken to continue; got {capped.get('nextToken')!r}"
    )

    # An unrestricted page picks up both newly-created groups -- the independent read that
    # proves CreateDbParameterGroup's effect is visible through ListDbParameterGroups.
    full = influx.list_db_parameter_groups(maxResults=100)
    listed = {item["name"] for item in full["items"]}
    assert set(names) <= listed, (
        f"both created groups {names!r} must appear in ListDbParameterGroups; "
        f"got {sorted(listed)!r}"
    )


def _client_error(fn):
    """Call fn(); return the botocore Error dict (Code and Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
