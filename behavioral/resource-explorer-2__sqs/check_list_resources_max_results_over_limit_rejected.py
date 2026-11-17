"""list-resources-max-results-over-limit-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-resources-max-results-over-limit-rejected"
GROUP = "validation"
SERVICES = ["resource-explorer-2", "sqs"]

_TAG_KEY = "sim2real-rexmr"
_OVER_LIMIT = ("ValidationException", "Invalid request body")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:resource-explorer-index")
def run(ctx) -> None:
    """ListResources rejects MaxResults=1001 with ValidationException and its exact message; the
    boundary value MaxResults=1000 keeps succeeding against the same view and query afterward.
    """
    rex = ctx.client("resource-explorer-2")
    sqs = ctx.client("sqs")

    _create_index_and_wait_active(ctx)

    tag_value = ctx.unique_name("sim2real-rexmr-")
    view_arn = rex.create_view(
        ViewName=ctx.unique_name("sim2real-rexmr-"),
        IncludedProperties=[{"Name": "tags"}],
        Tags={"sim2real-check": CHECK},
    )["View"]["ViewArn"]
    ctx.on_cleanup(_teardown(lambda: rex.delete_view(ViewArn=view_arn), "ResourceNotFoundException"))
    filter_string = f"tag:{_TAG_KEY}={tag_value}"

    qname = ctx.unique_name("sim2real-rexmr-")
    qurl = sqs.create_queue(QueueName=qname)["QueueUrl"]
    ctx.on_cleanup(_teardown(
        lambda: sqs.delete_queue(QueueUrl=qurl), "AWS.SimpleQueueService.NonExistentQueue",
    ))
    sqs.tag_queue(QueueUrl=qurl, Tags={_TAG_KEY: tag_value})
    qarn = sqs.get_queue_attributes(QueueUrl=qurl, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    # Positive control at the legal boundary: MaxResults=1000 is the largest accepted value and
    # must see our own queue before we probe one past it.
    baseline = _poll_until(
        lambda: rex.list_resources(ViewArn=view_arn, Filters={"FilterString": filter_string}, MaxResults=1000),
        lambda resp: [r["Arn"] for r in resp["Resources"]] == [qarn],
        timeout_s=90.0,
        interval_s=5.0,
    )
    assert baseline["Resources"][0]["Arn"] == qarn, (
        f"expected MaxResults=1000 to return our own queue, got {baseline['Resources']!r}"
    )

    got = _error(lambda: rex.list_resources(
        ViewArn=view_arn, Filters={"FilterString": filter_string}, MaxResults=1001
    ))
    assert got == _OVER_LIMIT, (
        f"expected MaxResults=1001 to be rejected with {_OVER_LIMIT!r}, got {got!r}"
    )

    # After the refusal, MaxResults=1000 on the same view and filter still returns exactly our queue.
    still_ok = rex.list_resources(ViewArn=view_arn, Filters={"FilterString": filter_string}, MaxResults=1000)
    assert [r["Arn"] for r in still_ok["Resources"]] == [qarn], (
        f"expected MaxResults=1000 to keep finding our queue after the rejected call, got "
        f"{still_ok['Resources']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
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
