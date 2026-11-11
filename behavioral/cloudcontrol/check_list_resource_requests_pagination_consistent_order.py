"""list-resource-requests-pagination-consistent-order."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-resource-requests-pagination-consistent-order"
GROUP = "ordering"
SERVICES = ["cloudcontrol"]

_N = 5


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paginating ListResourceRequests via NextToken yields the same order as a single large call, with no duplicates."""
    cc = ctx.client("cloudcontrol")
    tokens = []
    for i in range(_N):
        name = ctx.unique_name(f"sim2real-cc-pg-{i}-")
        queue = _create_queue(ctx, cc, name)
        tokens.append(queue["create_request_token"])

    # Narrow both the baseline and the paginated walk to CREATE requests. Real accounts
    # running this suite concurrently accumulate CREATE/UPDATE/DELETE history for many
    # unrelated resources; without this filter a page walk has to pass through all of it
    # to reach our (very recent, but not necessarily page-1) entries and can time out
    # before it gets there. The filter narrows the search space identically for both
    # calls, so the order-and-duplicates invariant under test is unchanged.
    op_filter = {"ResourceRequestStatusFilter": {"Operations": ["CREATE"]}}

    # Baseline: a single call wide enough to capture all 5 of our (very recent) requests.
    baseline = cc.list_resource_requests(MaxResults=100, **op_filter)["ResourceRequestStatusSummaries"]
    baseline_order = [s["RequestToken"] for s in baseline if s["RequestToken"] in tokens]
    assert len(baseline_order) == _N, (
        f"expected {_N} of our create requests in the single-page baseline listing, got {baseline_order}"
    )

    # Now paginate with a small (but not pathologically tiny) page size and reconstruct
    # the order of our requests.
    paginated_order = []
    seen = set()
    next_token = None
    pages = 0
    max_pages = 200
    while True:
        pages += 1
        if pages > max_pages:
            raise AssertionError(f"did not find all {_N} create requests within {max_pages} pages")
        kwargs = {"MaxResults": 25, **op_filter}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = cc.list_resource_requests(**kwargs)
        for s in resp["ResourceRequestStatusSummaries"]:
            rt = s["RequestToken"]
            assert rt not in seen, f"duplicate RequestToken {rt} seen across ListResourceRequests pages"
            seen.add(rt)
            if rt in tokens:
                paginated_order.append(rt)
        next_token = resp.get("NextToken")
        if len(paginated_order) >= _N or not next_token:
            break

    assert len(paginated_order) == _N, (
        f"expected to find all {_N} create requests while paginating, found {len(paginated_order)}"
    )
    assert paginated_order == baseline_order, (
        f"paginated order {paginated_order} does not match single-call order {baseline_order}"
    )


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
        _poll_progress(cc, resp["ProgressEvent"]["RequestToken"], timeout_s=60.0, interval_s=2.0)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "RequestTokenNotFoundException",
            "ResourceNotFoundException",
            "TypeNotFoundException",
        ):
            raise


def _create_queue(ctx, cc, name):
    """Submit CreateResource for an SQS queue, wait for SUCCESS, register delete cleanup."""
    desired = json.dumps({"QueueName": name, "Tags": [{"Key": "sim2real", "Value": CHECK}]})
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
