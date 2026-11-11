"""list-resources-pagination-no-duplicates-or-gaps."""
from __future__ import annotations

import concurrent.futures
import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-resources-pagination-no-duplicates-or-gaps"
GROUP = "ordering"
SERVICES = ["cloudcontrol"]

_N = 5


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paginating ListResources via NextToken over a stable snapshot returns each identifier exactly once."""
    cc = ctx.client("cloudcontrol")
    names = [ctx.unique_name(f"sim2real-cc-lr-{i}-") for i in range(_N)]
    # Each CreateResource->terminal-status round trip through CloudControl's provider
    # framework routinely takes tens of seconds on real AWS; five of them run
    # sequentially can exhaust the check's 300s body budget before ListResources is
    # even called. The 5 creations are independent, so run them concurrently and only
    # then register cleanup.
    with concurrent.futures.ThreadPoolExecutor(max_workers=_N) as pool:
        identifiers = list(pool.map(lambda name: _create_queue(cc, name), names))
    for ident in identifiers:
        ctx.on_cleanup(lambda i=ident: _delete_queue_quiet(cc, i))
    identifiers = set(identifiers)

    seen = set()
    found = set()
    next_token = None
    pages = 0
    max_pages = 500
    # Real accounts running this suite accumulate a lot of SQS queues from concurrently
    # running checks; MaxResults=2 forces so many round trips to page past that unrelated
    # inventory that the check can time out well before it reaches all of our (recently
    # created, but not necessarily early-page) queues. Use a larger page size while still
    # exercising multi-page pagination.
    while True:
        pages += 1
        if pages > max_pages:
            raise AssertionError(f"exceeded {max_pages} pages while paginating ListResources")
        kwargs = {"TypeName": "AWS::SQS::Queue", "MaxResults": 25}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = cc.list_resources(**kwargs)
        for rd in resp["ResourceDescriptions"]:
            ident = rd["Identifier"]
            assert ident not in seen, f"duplicate identifier {ident} seen across ListResources pages"
            seen.add(ident)
            if ident in identifiers:
                found.add(ident)
        next_token = resp.get("NextToken")
        if found == identifiers or not next_token:
            break

    assert found == identifiers, (
        f"expected all {_N} created queues to be listed exactly once, missing {identifiers - found}"
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


def _create_queue(cc, name):
    """Submit CreateResource for an SQS queue and wait for SUCCESS. Returns the identifier."""
    desired = json.dumps({"QueueName": name})
    resp = cc.create_resource(TypeName="AWS::SQS::Queue", DesiredState=desired)
    request_token = resp["ProgressEvent"]["RequestToken"]
    final = _poll_progress(cc, request_token)
    if final["OperationStatus"] != "SUCCESS":
        raise AssertionError(f"create queue {name} did not succeed: {final}")
    return final["Identifier"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
