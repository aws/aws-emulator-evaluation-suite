"""search-explicit-view-overrides-default."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "search-explicit-view-overrides-default"
GROUP = "search"
SERVICES = ["resource-explorer-2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:resource-explorer-index")
def run(ctx) -> None:
    """Search validates its query against the explicitly passed view, not the default: a tag.key:
    filter is refused against the default view, whose properties omit tags, and accepted with the
    ViewArn of a tags-enabled view.
    """
    from botocore.exceptions import ClientError

    rex = ctx.client("resource-explorer-2")
    _create_index_and_wait_active(ctx)

    default_view_arn = rex.create_view(ViewName=ctx.unique_name("sim2real-rexdefv-"))["View"]["ViewArn"]
    ctx.on_cleanup(lambda: _safe_delete_view(rex, default_view_arn))

    tags_view_arn = rex.create_view(
        ViewName=ctx.unique_name("sim2real-rexotherv-"),
        IncludedProperties=[{"Name": "tags"}],
    )["View"]["ViewArn"]
    ctx.on_cleanup(lambda: _safe_delete_view(rex, tags_view_arn))

    prior_default = rex.get_default_view().get("ViewArn")
    had_prior_default = prior_default is not None

    def _restore_prior_default() -> None:
        if had_prior_default:
            rex.associate_default_view(ViewArn=prior_default)
        else:
            try:
                rex.disassociate_default_view()
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise

    ctx.on_cleanup(_restore_prior_default)

    rex.associate_default_view(ViewArn=default_view_arn)
    got = rex.get_default_view()["ViewArn"]
    assert got == default_view_arn, f"expected default view {default_view_arn!r}, got {got!r}"

    # positive control: with no explicit ViewArn, Search falls back to the default view, whose
    # schema has no tags property -- the tag.key: filter must be rejected.
    default_error = _error(lambda: rex.search(QueryString="tag.key:sim2real-env"))
    expected = (
        "ValidationException",
        "The specified filter tag.key is not valid because it uses properties that are not "
        "included in the view.",
    )
    assert default_error == expected, (
        f"expected default (no-tags) view to reject tag.key: filter with {expected!r}, "
        f"got {default_error!r}"
    )

    # the identical filter, with an explicit ViewArn naming the tags-enabled view, must succeed --
    # Search resolved the passed ViewArn's schema, not the account's default, to validate the query.
    resp = rex.search(QueryString="tag.key:sim2real-env", ViewArn=tags_view_arn)
    assert resp["ViewArn"] == tags_view_arn, f"expected response ViewArn {tags_view_arn!r}, got {resp['ViewArn']!r}"
    assert "Count" in resp, f"expected a Count block in the response, got keys {sorted(resp)!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
    """Use the Region's index, creating one only when the account has none.

    The index is one per account and Region, so a pre-existing one is left exactly as found; only
    an index this check created is deleted at cleanup.
    """
    from botocore.exceptions import ClientError

    rex = ctx.client("resource-explorer-2")
    try:
        existing = rex.get_index()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        existing = {}
    if existing.get("Arn") and existing.get("State") != "DELETED":
        arn = existing["Arn"]
    else:
        arn = rex.create_index()["Arn"]

        def _cleanup() -> None:
            rex.delete_index(Arn=arn)
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
