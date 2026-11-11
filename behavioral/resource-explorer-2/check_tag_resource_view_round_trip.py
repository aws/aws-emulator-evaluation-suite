"""tag-resource-view-round-trip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-resource-view-round-trip"
GROUP = "tagging"
SERVICES = ["resource-explorer-2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:resource-explorer-index")
def run(ctx) -> None:
    """TagResource/ListTagsForResource/UntagResource round-trip on a view: tags persist, and
    untagging one key leaves the others intact."""

    rex = ctx.client("resource-explorer-2")
    _create_index_and_wait_active(ctx)
    view_arn = rex.create_view(ViewName=ctx.unique_name("sim2real-rextag-"))["View"]["ViewArn"]
    ctx.on_cleanup(lambda: _safe_delete(rex, view_arn))

    initial = rex.list_tags_for_resource(resourceArn=view_arn)["Tags"]
    assert initial == {}, f"expected a freshly created view to carry no tags, got {initial!r}"

    rex.tag_resource(resourceArn=view_arn, Tags={"env": "sim2real", "team": "qa"})
    tags = rex.list_tags_for_resource(resourceArn=view_arn)["Tags"]
    assert tags == {"env": "sim2real", "team": "qa"}, f"expected both tags after TagResource, got {tags!r}"

    rex.untag_resource(resourceArn=view_arn, tagKeys=["team"])
    tags_after = rex.list_tags_for_resource(resourceArn=view_arn)["Tags"]
    assert tags_after == {"env": "sim2real"}, f"expected only 'env' to remain after untagging 'team', got {tags_after!r}"
    assert "team" not in tags_after, f"'team' key should have been removed by UntagResource, still present in {tags_after!r}"


import time


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
    try:
        arn = rex.create_index()["Arn"]
        created_here = True
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ConflictException":
            raise
        # An index is one-per-region-per-account: adopt the existing one rather than
        # failing, and only tear down what this check actually created.
        arn = rex.get_index()["Arn"]
        created_here = False

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


def _safe_delete(rex, arn) -> None:
    from botocore.exceptions import ClientError

    try:
        rex.delete_view(ViewArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
