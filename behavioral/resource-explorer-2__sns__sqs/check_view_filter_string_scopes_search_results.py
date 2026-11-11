"""view-filter-string-scopes-search-results."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "view-filter-string-scopes-search-results"
GROUP = "cross-service-scoping"
SERVICES = ["resource-explorer-2", "sns", "sqs"]


@tags("axis:happy-path", "cap:c3", "concern:representation", "plane:control", "resource:account-singleton:resource-explorer-index")
def run(ctx) -> None:
    """A view filtered on `resourcetype:sqs:queue` returns, through ListResources, the check's SQS
    queue and never the SNS topic indexed alongside it in the same index.
    """
    rex = ctx.client("resource-explorer-2")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    _create_index_and_wait_active(ctx)

    topic_name = ctx.unique_name("sim2real-xsvc-rexscope-")
    topic_arn = sns.create_topic(Name=topic_name, Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    queue_name = ctx.unique_name("sim2real-xsvc-rexscope-")
    queue_url = sqs.create_queue(QueueName=queue_name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    # Wait for the index to pick up BOTH resources before asserting anything about scoping --
    # otherwise an empty filtered result would be indistinguishable from "not indexed yet".
    _poll_until(
        lambda: {r["Arn"] for r in _list_all(rex, Filters={"FilterString": f"service:sns"})},
        lambda arns: topic_arn in arns,
        timeout_s=120.0,
        interval_s=5.0,
    )
    _poll_until(
        lambda: {r["Arn"] for r in _list_all(rex, Filters={"FilterString": f"service:sqs"})},
        lambda arns: queue_arn in arns,
        timeout_s=120.0,
        interval_s=5.0,
    )

    view_arn = rex.create_view(
        ViewName=ctx.unique_name("sim2real-xsvc-rexscope-"),
        Filters={"FilterString": "resourcetype:sqs:queue"},
        Tags={"sim2real": CHECK},
    )["View"]["ViewArn"]
    ctx.on_cleanup(lambda: _safe_delete_view(rex, view_arn))

    resources = _list_all(rex, ViewArn=view_arn)
    arns = {r["Arn"] for r in resources}
    assert queue_arn in arns, (
        f"expected the resourcetype:sqs:queue view to return our own queue {queue_arn!r}, "
        f"got arns={sorted(arns)!r}"
    )
    assert topic_arn not in arns, (
        f"expected the resourcetype:sqs:queue view to NEVER return our SNS topic {topic_arn!r}, "
        f"but it was present among arns={sorted(arns)!r}"
    )
    for r in resources:
        assert r["ResourceType"] == "sqs:queue", (
            f"expected every resource under the resourcetype:sqs:queue view to report "
            f"ResourceType='sqs:queue', got {r['ResourceType']!r} for {r['Arn']!r}"
        )
        assert r["Service"] == "sqs", (
            f"expected every resource under the resourcetype:sqs:queue view to report "
            f"Service='sqs', got {r['Service']!r} for {r['Arn']!r}"
        )


def _list_all(rex, **kwargs) -> list[dict]:
    out: list[dict] = []
    token = None
    while True:
        page = rex.list_resources(**({"NextToken": token} if token else {}), MaxResults=100, **kwargs)
        out.extend(page["Resources"])
        token = page.get("NextToken")
        if not token:
            return out


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
    from botocore.exceptions import ClientError

    rex = ctx.client("resource-explorer-2")
    created_here = False
    try:
        arn = rex.create_index(Tags={"sim2real": CHECK})["Arn"]
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
    from botocore.exceptions import ClientError

    rex = ctx.client("resource-explorer-2")

    def _probe():
        try:
            return rex.get_index()["State"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return "GONE"
            raise

    _poll_until(_probe, lambda s: s in ("GONE", "DELETED"), timeout_s=timeout_s, interval_s=interval_s)


def _safe_delete_view(rex, arn) -> None:
    from botocore.exceptions import ClientError

    try:
        rex.delete_view(ViewArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
