"""negative-dynamic-thing-group-invalid-query-blocked."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "negative-dynamic-thing-group-invalid-query-blocked"
GROUP = "overly-permissive"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """CreateDynamicThingGroup with a malformed fleet-indexing query string is
    rejected with InvalidQueryException rather than creating a group that never
    matches, while the same call with a syntactically valid query succeeds."""
    iot = ctx.client("iot")

    prev_cfg = iot.get_indexing_configuration().get(
        "thingIndexingConfiguration", {"thingIndexingMode": "OFF"}
    )

    def _restore_indexing():
        iot.update_indexing_configuration(thingIndexingConfiguration=prev_cfg)

    ctx.on_cleanup(_restore_indexing)
    iot.update_indexing_configuration(thingIndexingConfiguration={"thingIndexingMode": "REGISTRY"})
    _wait_index_active(iot)

    bad_group_name = ctx.unique_name("sim2real-badquery-group")
    code, message = _error(
        lambda: iot.create_dynamic_thing_group(
            thingGroupName=bad_group_name,
            # Unbalanced parenthesis / dangling operator: invalid Fleet
            # Indexing query syntax.
            queryString="thingName:((AND",
        )
    )
    assert code == "InvalidQueryException", f"expected InvalidQueryException, got {code}"
    assert message == "Unable to parse query, invalid syntax", message

    not_found_code, not_found_message = _error(lambda: iot.describe_thing_group(thingGroupName=bad_group_name))
    assert not_found_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {not_found_code}"
    )
    assert not_found_message == f"ThingGroup {ctx.account}:{bad_group_name} not found.", not_found_message

    # Positive control: a well-formed query on the same index succeeds.
    good_group_name = ctx.unique_name("sim2real-goodquery-group")
    iot.create_dynamic_thing_group(
        thingGroupName=good_group_name,
        queryString="thingName:*",
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iot.delete_dynamic_thing_group(thingGroupName=good_group_name))
    described = iot.describe_thing_group(thingGroupName=good_group_name)
    assert described["thingGroupName"] == good_group_name, (
        f"expected thingGroupName {good_group_name!r}, got {described['thingGroupName']!r}"
    )
    assert described["queryString"] == "thingName:*", (
        f"expected queryString 'thingName:*', got {described['queryString']!r}"
    )

    # Teardown as a free negative: delete it now, then prove it is gone and unusable.
    iot.delete_dynamic_thing_group(thingGroupName=good_group_name)
    gone_code, gone_message = _error(lambda: iot.describe_thing_group(thingGroupName=good_group_name))
    assert gone_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {gone_code}"
    )
    assert gone_message == f"ThingGroup {ctx.account}:{good_group_name} not found.", gone_message


def _wait_index_active(iot, index_name: str = "AWS_Things", timeout_s: float = 120.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = iot.describe_index(indexName=index_name)
            if resp.get("indexStatus") == "ACTIVE":
                return
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(3)
    raise AssertionError(f"index {index_name} never became ACTIVE within {timeout_s}s")


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
