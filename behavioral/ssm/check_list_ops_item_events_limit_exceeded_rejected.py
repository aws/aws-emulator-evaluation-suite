"""list-ops-item-events-limit-exceeded-rejected."""
from __future__ import annotations

import re
from behavioral_harness import tags

CHECK = "list-ops-item-events-limit-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm"]


# AWS appends the request id of the inner service call to this message; it is the only part
# that varies per call.
_REQUEST_ID = re.compile(r"Request ID: [0-9A-Za-z-]+")


def _stable(message):
    if message is None:
        return None
    return _REQUEST_ID.sub("Request ID: <request-id>", message)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListOpsItemEvents with a Values list on the OpsItemId filter that is far larger than the
    service's supported filter size fails with OpsItemInvalidParameterException instead of
    silently truncating and returning a partial match."""
    ssm = ctx.client("ssm")

    created_ids = []
    for i in range(2):
        item = ssm.create_ops_item(
            Description=f"sim2real fidelity check item {i}",
            Source="sim2real",
            Title=ctx.unique_name("sim2real-opsitem-events-"),
        )
        opsitem_id = item["OpsItemId"]
        created_ids.append(opsitem_id)
        ctx.on_cleanup(lambda oid=opsitem_id: ssm.delete_ops_item(OpsItemId=oid))

    # Positive control: filtering by a single, valid OpsItem id succeeds normally (the service
    # caps Values at 1 entry per OpsItemId filter), and only ever returns events for the
    # filtered id -- never the sibling OpsItem's events.
    ok = ssm.list_ops_item_events(
        Filters=[{"Key": "OpsItemId", "Values": [created_ids[0]], "Operator": "Equal"}]
    )
    assert "Summaries" in ok, ok
    assert all(e["OpsItemId"] == created_ids[0] for e in ok["Summaries"]), ok["Summaries"]

    # Negative: an oversized Values list (well past any plausible per-filter cap) on the same
    # filter shape is rejected outright.
    oversized_values = [f"oi-{i:012x}" for i in range(200)]
    err = _error(
        lambda: ssm.list_ops_item_events(
            Filters=[{"Key": "OpsItemId", "Values": oversized_values, "Operator": "Equal"}]
        )
    )
    assert err["Code"] == "OpsItemInvalidParameterException", f"unexpected error: {err!r}"
    # AWS appends a per-request request id; it is the only varying part.
    expected = (
        "Maximum number of OpsItemEvent filter values exceeded (Service: AmazonSSM; Status Code: 400; "
        "Error Code: OpsItemInvalidParameterException; Request ID: <request-id>; Proxy: null)"
    )
    assert _stable(err.get("Message")) == expected, f"expected message {expected!r}, got {err!r}"

    # Positive control (repeat): the API still works normally right after the rejection --
    # the oversized filter didn't leave the service in a broken state.
    ok_again = ssm.list_ops_item_events(
        Filters=[{"Key": "OpsItemId", "Values": [created_ids[0]], "Operator": "Equal"}]
    )
    assert "Summaries" in ok_again, ok_again
    assert all(e["OpsItemId"] == created_ids[0] for e in ok_again["Summaries"]), ok_again["Summaries"]


def _error(fn):
    """Call fn(); return its botocore Error dict (Code and Message). An unexpected success
    raises, so an emulator accepting what AWS refuses never reads as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError, the call unexpectedly succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
