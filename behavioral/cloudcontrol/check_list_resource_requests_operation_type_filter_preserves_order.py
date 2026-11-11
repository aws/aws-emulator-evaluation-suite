"""list-resource-requests-operation-type-filter-preserves-order."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-resource-requests-operation-type-filter-preserves-order"
GROUP = "ordering"
SERVICES = ["cloudcontrol"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListResourceRequests filtered by Operations=UPDATE returns only UPDATE entries and
    keeps our two updates in the same relative order as the unfiltered listing.
    """
    cc = ctx.client("cloudcontrol")
    name = ctx.unique_name("sim2real-cc-optfilter-")
    queue = _create_queue(ctx, cc, name)
    identifier = queue["identifier"]

    # The schema types MessageRetentionPeriod as an integer; a string is a ValidationException.
    patch1 = json.dumps([{"op": "add", "path": "/MessageRetentionPeriod", "value": 345600}])
    r1 = cc.update_resource(TypeName="AWS::SQS::Queue", Identifier=identifier, PatchDocument=patch1)
    tok1 = r1["ProgressEvent"]["RequestToken"]
    f1 = _poll_progress(cc, tok1)
    assert f1["OperationStatus"] == "SUCCESS", f"first update failed: {f1}"

    patch2 = json.dumps([{"op": "add", "path": "/MessageRetentionPeriod", "value": 86400}])
    r2 = cc.update_resource(TypeName="AWS::SQS::Queue", Identifier=identifier, PatchDocument=patch2)
    tok2 = r2["ProgressEvent"]["RequestToken"]
    f2 = _poll_progress(cc, tok2)
    assert f2["OperationStatus"] == "SUCCESS", f"second update failed: {f2}"

    # Raw list order is not documented as chronological, so only relative order is compared.
    wanted = {tok1, tok2}

    unfiltered = _list_all_requests(cc)
    order_unfiltered = [s["RequestToken"] for s in unfiltered if s["RequestToken"] in wanted]
    assert set(order_unfiltered) == wanted, (
        f"expected both update requests visible in the unfiltered listing, got {order_unfiltered}"
    )

    filtered = _list_all_requests(cc, ResourceRequestStatusFilter={"Operations": ["UPDATE"]})
    order_filtered = [s["RequestToken"] for s in filtered if s["RequestToken"] in wanted]

    assert filtered, "expected at least the two UPDATE requests we just issued"
    assert all(s["Operation"] == "UPDATE" for s in filtered), (
        "Operations=['UPDATE'] filter leaked a non-UPDATE entry"
    )
    assert set(order_filtered) == wanted, (
        f"expected both update requests visible in the UPDATE-filtered listing, got {order_filtered}"
    )
    assert order_filtered == order_unfiltered, (
        "Operations=['UPDATE'] filter changed the relative order of our own update requests: "
        f"unfiltered={order_unfiltered} filtered={order_filtered}"
    )


def _list_all_requests(cc, **kwargs):
    """Every ListResourceRequests summary across all pages, in listing order."""
    summaries, token = [], None
    while True:
        page = cc.list_resource_requests(MaxResults=100, **kwargs, **({"NextToken": token} if token else {}))
        summaries.extend(page["ResourceRequestStatusSummaries"])
        token = page.get("NextToken")
        if not token:
            return summaries


def _poll_progress(cc, request_token, timeout_s=180.0, interval_s=3.0):
    """Poll GetResourceRequestStatus until the request reaches a terminal OperationStatus."""
    terminal = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cc.get_resource_request_status(RequestToken=request_token)
        last = resp["ProgressEvent"]
        if last["OperationStatus"] in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {request_token} did not reach a terminal state within {timeout_s}s (last={last})")


def _delete_queue_quiet(cc, identifier):
    try:
        resp = cc.delete_resource(TypeName="AWS::SQS::Queue", Identifier=identifier)
        _poll_progress(cc, resp["ProgressEvent"]["RequestToken"], timeout_s=180.0, interval_s=2.0)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "RequestTokenNotFoundException",
            "ResourceNotFoundException",
            "TypeNotFoundException",
        ):
            raise


def _create_queue(ctx, cc, name):
    """Submit CreateResource for an SQS queue, wait for SUCCESS, register delete cleanup."""
    desired = json.dumps({"QueueName": name})
    resp = cc.create_resource(TypeName="AWS::SQS::Queue", DesiredState=desired)
    request_token = resp["ProgressEvent"]["RequestToken"]
    final = _poll_progress(cc, request_token)
    if final["OperationStatus"] != "SUCCESS":
        raise AssertionError(f"create queue {name} did not succeed: {final}")
    identifier = final["Identifier"]
    ctx.on_cleanup(lambda ident=identifier: _delete_queue_quiet(cc, ident))
    return {"identifier": identifier, "create_request_token": request_token}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
