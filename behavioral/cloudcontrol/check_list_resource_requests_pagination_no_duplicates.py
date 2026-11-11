"""list-resource-requests-pagination-no-duplicates."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-resource-requests-pagination-no-duplicates"
GROUP = "ordering"
SERVICES = ["cloudcontrol"]

_WALK_ATTEMPTS = 3


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paginating ListResourceRequests with a small page size never repeats or skips a
    RequestToken: every request we submitted appears in exactly one page, exactly once, and in
    the same relative order as a walk with large (MaxResults=100) pages."""
    cc = ctx.client("cloudcontrol")
    submitted_tokens: list[str] = []
    identifiers: list[str] = []

    for _ in range(4):
        name = ctx.unique_name("sim2real-cc-reqpg-")
        progress = cc.create_resource(
            TypeName="AWS::SNS::Topic",
            DesiredState=json.dumps(
                {"TopicName": name, "Tags": [{"Key": "sim2real", "Value": "true"}]}
            ),
        )["ProgressEvent"]
        token = progress["RequestToken"]
        final, _ = _wait_terminal(cc, token)
        assert final["OperationStatus"] == "SUCCESS", f"topic create failed: {final}"
        submitted_tokens.append(token)
        identifiers.append(final["Identifier"])
        ctx.on_cleanup(lambda ident=final["Identifier"]: _delete_resource(cc, "AWS::SNS::Topic", ident))

    wanted = set(submitted_tokens)

    # Large pages read to the end establish the reference relative order of our own requests.
    reference_order = [token for token in _walk(cc, max_results=100) if token in wanted]
    assert len(reference_order) == 4, f"expected all 4 requests in the reference walk, got {reference_order}"

    # Now paginate one request at a time and verify no duplicates/skips of our own tokens, and that
    # their relative order matches the reference order exactly. Requests other callers submit
    # during a walk can shift its pages, so a walk that misses or repeats one of ours is read
    # again, a bounded number of times; the last walk is graded.
    for _ in range(_WALK_ATTEMPTS):
        pages = 0
        paginated_tokens: list[str] = []
        next_token = None
        for _ in range(500):
            page = _list_page(cc, max_results=1, next_token=next_token)
            pages += 1
            paginated_tokens.extend(
                s["RequestToken"]
                for s in page.get("ResourceRequestStatusSummaries", [])
                if s["RequestToken"] in wanted
            )
            next_token = page.get("NextToken")
            if not next_token or len(set(paginated_tokens)) >= 4:
                break
        if len(paginated_tokens) == 4 and set(paginated_tokens) == wanted:
            break

    assert pages >= 4, f"expected pagination across at least 4 single-item pages, got {pages}"
    assert len(paginated_tokens) == len(set(paginated_tokens)), (
        f"one of our RequestTokens repeated across ListResourceRequests pages: {paginated_tokens}"
    )
    assert len(paginated_tokens) == 4, f"expected all 4 of our requests across pages, got {paginated_tokens}"
    assert paginated_tokens == reference_order, (
        f"paginated order {paginated_tokens} diverged from the large-page reference order {reference_order}"
    )


def _walk(cc, max_results: int) -> list[str]:
    """Every CREATE RequestToken across all pages of max_results, in listing order."""
    tokens: list[str] = []
    next_token = None
    while True:
        page = _list_page(cc, max_results=max_results, next_token=next_token)
        tokens.extend(s["RequestToken"] for s in page.get("ResourceRequestStatusSummaries", []))
        next_token = page.get("NextToken")
        if not next_token:
            return tokens


def _list_page(cc, max_results: int, next_token: str | None) -> dict:
    kwargs: dict = {"MaxResults": max_results, "ResourceRequestStatusFilter": {"Operations": ["CREATE"]}}
    if next_token:
        kwargs["NextToken"] = next_token
    return cc.list_resource_requests(**kwargs)


def _wait_terminal(cc, request_token: str, timeout_s: float = 120.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    history: list[str] = []
    while time.monotonic() < deadline:
        last = cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]
        history.append(last["OperationStatus"])
        if last["OperationStatus"] in ("SUCCESS", "FAILED", "CANCEL_COMPLETE"):
            return last, history
        time.sleep(interval_s)
    raise AssertionError(f"request {request_token} never reached terminal status, last={last}")


def _delete_resource(cc, type_name: str, identifier: str) -> None:
    try:
        token = cc.delete_resource(TypeName=type_name, Identifier=identifier)["ProgressEvent"]["RequestToken"]
        _wait_terminal(cc, token, timeout_s=60.0)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "RequestTokenNotFoundException",
            "ResourceNotFoundException",
            "TypeNotFoundException",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
