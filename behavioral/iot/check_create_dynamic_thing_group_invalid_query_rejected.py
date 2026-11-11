"""create-dynamic-thing-group-invalid-query-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-dynamic-thing-group-invalid-query-rejected"
GROUP = "negative-classes"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """CreateDynamicThingGroup with a malformed query string fails with InvalidQueryException and
    creates no group; the same call with a valid query string succeeds."""
    iot = ctx.client("iot")

    restore = _ensure_registry_indexing_active(iot)
    if restore is not None:
        ctx.on_cleanup(restore)

    bad_group = ctx.unique_name("sim2real-dtg-bad-")
    good_group = ctx.unique_name("sim2real-dtg-good-")
    tag_list = [{"Key": "sim2real-check", "Value": CHECK}]

    err = _error(
        lambda: iot.create_dynamic_thing_group(
            thingGroupName=bad_group,
            queryString="thingTypeName:( AND OR )::malformed",
            tags=tag_list,
        )
    )
    assert err == ("InvalidQueryException", "Unable to parse query, invalid syntax"), err

    # effect absent: the malformed group must not have been created
    err_after = _error(lambda: iot.describe_thing_group(thingGroupName=bad_group))
    assert err_after == ("ResourceNotFoundException", f"ThingGroup {ctx.account}:{bad_group} not found."), err_after

    # positive control: a syntactically valid query string succeeds
    iot.create_dynamic_thing_group(
        thingGroupName=good_group, queryString="thingName:*", tags=tag_list
    )
    ctx.on_cleanup(lambda: iot.delete_dynamic_thing_group(thingGroupName=good_group))
    got = iot.describe_thing_group(thingGroupName=good_group)
    assert got["thingGroupName"] == good_group, (
        f"expected thingGroupName {good_group!r}, got {got.get('thingGroupName')!r}"
    )
    assert got["queryString"] == "thingName:*", (
        f"expected queryString 'thingName:*', got {got.get('queryString')!r}"
    )


def _error(fn):
    """Call fn(); return its (error code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _ensure_registry_indexing_active(iot):
    current = iot.get_indexing_configuration()
    prior_mode = current.get("thingIndexingConfiguration", {}).get("thingIndexingMode", "OFF")

    if prior_mode == "OFF":
        iot.update_indexing_configuration(
            thingIndexingConfiguration={"thingIndexingMode": "REGISTRY"}
        )

        def restore():
            iot.update_indexing_configuration(
                thingIndexingConfiguration={"thingIndexingMode": "OFF"}
            )
    else:
        restore = None

    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        status = iot.describe_index(indexName="AWS_Things")["indexStatus"]
        if status == "ACTIVE":
            return restore
        time.sleep(2)
    raise AssertionError("AWS_Things index never became ACTIVE")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
