"""search-and-list-resources-filter-string-validation-differs."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "search-and-list-resources-filter-string-validation-differs"
GROUP = "negative-classes"
SERVICES = ["resource-explorer-2"]

_BAD_FILTER = (
    "ValidationException",
    "FilterString must contain only AREX supported filter operators and no freeform text.",
)


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control",
      "resource:account-singleton:resource-explorer-index")
def run(ctx) -> None:
    """ListResources rejects a bare 'service:' Filters.FilterString with ValidationException and its
    exact message, but Search accepts the identical string in QueryString and completes with no
    matches; both echo the same view's ViewArn for the well-formed 'service:sqs'."""
    rex = ctx.client("resource-explorer-2")
    _create_index_and_wait_active(ctx)

    view_arn = rex.create_view(
        ViewName=ctx.unique_name("sim2real-rexqrysrch-"), Tags={"sim2real-check": CHECK}
    )["View"]["ViewArn"]
    ctx.on_cleanup(_teardown_view(rex, view_arn))

    expect_error(
        lambda: rex.list_resources(ViewArn=view_arn, Filters={"FilterString": "service:"}, MaxResults=5),
        *_BAD_FILTER,
    )

    # Positive control: the well-formed neighbour keeps succeeding on the same view.
    list_ok = rex.list_resources(ViewArn=view_arn, Filters={"FilterString": "service:sqs"}, MaxResults=5)
    assert isinstance(list_ok["Resources"], list), (
        f"ListResources with a well-formed filter must return a Resources list, got {list_ok!r}"
    )
    assert list_ok["ViewArn"] == view_arn, (
        f"ListResources ViewArn {list_ok['ViewArn']!r} does not echo the view {view_arn!r}"
    )

    # Search's QueryString is not restricted to filter-operator syntax the way ListResources'
    # Filters.FilterString is: the identical 'service:' string is accepted, not rejected, and
    # resolves to a completed search with no matches in this account.
    search_colon = rex.search(QueryString="service:", ViewArn=view_arn, MaxResults=5)
    assert search_colon["Resources"] == [], (
        f"expected an empty Resources list for a freeform 'service:' query, got {search_colon!r}"
    )
    assert search_colon["Count"] == {"TotalResources": 0, "Complete": True}, (
        f"expected a completed, zero-result Count, got {search_colon['Count']!r}"
    )
    assert search_colon["ViewArn"] == view_arn, (
        f"Search ViewArn {search_colon['ViewArn']!r} does not echo the view {view_arn!r}"
    )

    # Search also accepts the well-formed operator form, on the same view.
    search_ok = rex.search(QueryString="service:sqs", ViewArn=view_arn, MaxResults=5)
    assert isinstance(search_ok["Resources"], list), (
        f"Search with a well-formed filter must return a Resources list, got {search_ok!r}"
    )
    assert search_ok["ViewArn"] == view_arn, (
        f"Search ViewArn {search_ok['ViewArn']!r} does not echo the view {view_arn!r}"
    )

    # After both Search calls, ListResources still refuses the bare 'service:' FilterString.
    expect_error(
        lambda: rex.list_resources(ViewArn=view_arn, Filters={"FilterString": "service:"}, MaxResults=5),
        *_BAD_FILTER,
    )


def _teardown_view(rex, view_arn):
    def run_undo() -> None:
        try:
            rex.delete_view(ViewArn=view_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    return run_undo


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed={last!r}")


def _create_index_and_wait_active(ctx) -> str:
    rex = ctx.client("resource-explorer-2")
    created_here = False
    try:
        arn = rex.create_index(Tags={"sim2real-check": CHECK})["Arn"]
        created_here = True
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ConflictException":
            raise
        arn = rex.get_index()["Arn"]

    if created_here:
        def _cleanup() -> None:
            try:
                rex.delete_index(Arn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
                return
            _poll_index_gone(ctx)

        ctx.on_cleanup(_cleanup)

    _poll_until(lambda: rex.get_index()["State"], lambda s: s == "ACTIVE", timeout_s=90.0, interval_s=3.0)
    return arn


def _poll_index_gone(ctx, timeout_s=90.0, interval_s=3.0) -> None:
    rex = ctx.client("resource-explorer-2")

    def _probe():
        try:
            return rex.get_index()["State"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return "GONE"
            raise

    _poll_until(_probe, lambda s: s in ("GONE", "DELETED"), timeout_s=timeout_s, interval_s=interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
