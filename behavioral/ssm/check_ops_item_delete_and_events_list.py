"""ops-item-delete-and-events-list."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ops-item-delete-and-events-list"
GROUP = "state-machine"
SERVICES = ["ssm"]


# AWS appends the request id of the inner service call to this message; it is the only part
# that varies per call.
_REQUEST_ID = re.compile(r"Request ID: [0-9A-Za-z-]+")


def _stable(message):
    if message is None:
        return None
    return _REQUEST_ID.sub("Request ID: <request-id>", message)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteOpsItem is idempotent and leaves the OpsItem readable via GetOpsItem and
    ListOpsItemEvents; for a never-created id GetOpsItem raises OpsItemNotFoundException
    while DeleteOpsItem still succeeds."""
    ssm = ctx.client("ssm")
    title = ctx.unique_name("sim2real-opsitem-")
    ops_item_id = ssm.create_ops_item(
        Title=title, Description="sim2real behavioral test ops item", Source="sim2real"
    )["OpsItemId"]

    summaries = _poll_describe(ssm, ops_item_id, lambda s: len(s) == 1)
    assert len(summaries) == 1, summaries
    assert summaries[0]["Title"] == title, summaries[0]

    # CreateOpsItem need not populate event history, so the result may be empty.
    events = ssm.list_ops_item_events(
        Filters=[{"Key": "OpsItemId", "Values": [ops_item_id], "Operator": "Equal"}]
    )["Summaries"]
    assert all(e["OpsItemId"] == ops_item_id for e in events), events

    ssm.delete_ops_item(OpsItemId=ops_item_id)

    # DeleteOpsItem does not remove the OpsItem from read paths, even well past any propagation lag.
    get_resp = ssm.get_ops_item(OpsItemId=ops_item_id)
    assert get_resp["OpsItem"]["Title"] == title, get_resp["OpsItem"]

    events_after = ssm.list_ops_item_events(
        Filters=[{"Key": "OpsItemId", "Values": [ops_item_id], "Operator": "Equal"}]
    )["Summaries"]
    assert all(e["OpsItemId"] == ops_item_id for e in events_after), events_after

    # Re-deleting an already-deleted OpsItem succeeds.
    ssm.delete_ops_item(OpsItemId=ops_item_id)

    # Flipping the last character yields a same-shaped id that was never created.
    fake_ops_item_id = ops_item_id[:-1] + ("0" if ops_item_id[-1] != "0" else "1")
    fake_get = _error(lambda: ssm.get_ops_item(OpsItemId=fake_ops_item_id))
    assert fake_get["Code"] == "OpsItemNotFoundException", fake_get
    # AWS appends a per-request request id; it is the only varying part.
    expected = (
        "OpsItem not found. (Service: AmazonSSM; Status Code: 400; Error Code: "
        "OpsItemNotFoundException; Request ID: <request-id>; Proxy: null)"
    )
    assert _stable(fake_get.get("Message")) == expected, f"expected message {expected!r}, got {fake_get!r}"

    # DeleteOpsItem has no existence check, so a never-created id also succeeds.
    ssm.delete_ops_item(OpsItemId=fake_ops_item_id)






def _describe(ssm, ops_item_id: str):
    return ssm.describe_ops_items(
        OpsItemFilters=[{"Key": "OpsItemId", "Values": [ops_item_id], "Operator": "Equal"}]
    )["OpsItemSummaries"]


def _poll_describe(ssm, ops_item_id: str, predicate, attempts: int = 15, delay: float = 2.0):
    """DescribeOpsItems is backed by an eventually-consistent index; a
    just-created/deleted OpsItem may not be reflected immediately."""
    summaries = _describe(ssm, ops_item_id)
    for _ in range(attempts):
        if predicate(summaries):
            return summaries
        time.sleep(delay)
        summaries = _describe(ssm, ops_item_id)
    return summaries


def _error(fn):
    """Call fn() and return its botocore Error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, the call unexpectedly succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
