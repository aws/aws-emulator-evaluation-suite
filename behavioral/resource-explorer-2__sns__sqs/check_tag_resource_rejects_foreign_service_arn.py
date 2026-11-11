"""tag-resource-rejects-foreign-service-arn."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-resource-rejects-foreign-service-arn"
GROUP = "tagging"
SERVICES = ["resource-explorer-2", "sns", "sqs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:resource-explorer-index")
def run(ctx) -> None:
    """resource-explorer-2 TagResource rejects an SNS topic ARN with UnauthorizedException and
    attaches no tag, while the identical call on its own view ARN succeeds."""

    rex = ctx.client("resource-explorer-2")
    sns = ctx.client("sns")

    topic_name = ctx.unique_name("sim2real-xsvc-rextagforeign-")
    topic_arn = sns.create_topic(Name=topic_name)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    code, code_msg = _error(lambda: rex.tag_resource(resourceArn=topic_arn, Tags={"k": "v"}))
    assert code == "UnauthorizedException", (
        f"expected TagResource against a foreign-service (SNS) ARN to be rejected with "
        f"UnauthorizedException, got {code!r}"
    )
    want = "Unauthorized"
    assert code_msg == want, f"the foreign-ARN TagResource said {code_msg!r}, expected {want!r}"

    # effect absent: SNS's own view of the topic's tags shows nothing was attached
    sns_tags = sns.list_tags_for_resource(ResourceArn=topic_arn)["Tags"]
    assert sns_tags == [], (
        f"expected the rejected TagResource call to attach nothing to the SNS topic, got "
        f"Tags={sns_tags!r}"
    )

    # positive control: the identical call against resource-explorer-2's OWN resource succeeds
    _create_index_and_wait_active(ctx)
    view_arn = rex.create_view(ViewName=ctx.unique_name("sim2real-xsvc-rextagforeign-"))["View"][
        "ViewArn"
    ]
    ctx.on_cleanup(lambda: _safe_delete_view(rex, view_arn))

    rex.tag_resource(resourceArn=view_arn, Tags={"k": "v"})
    view_tags = rex.list_tags_for_resource(resourceArn=view_arn)["Tags"]
    assert view_tags == {"k": "v"}, (
        f"positive control: expected TagResource against our own view ARN to succeed and "
        f"persist, got Tags={view_tags!r}"
    )


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


def _error(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, so accepting
    input AWS refuses is not reported as a mere error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response.get("Error", {}).get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
