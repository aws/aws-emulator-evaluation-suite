"""create-view-invalid-name-pattern-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-view-invalid-name-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["resource-explorer-2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:resource-explorer-index")
def run(ctx) -> None:
    """CreateView with a ViewName over the 64-character limit is refused with UnauthorizedException
    ("Unauthorized") and persists no view under that name, while a compliant name in the same Region
    is created and reads back.
    """

    rex = ctx.client("resource-explorer-2")
    _create_index_and_wait_active(ctx, tags={"sim2real": CHECK})
    # 64-char max length is a hard, unambiguous constraint (unlike disallowed characters, which
    # this service does not reliably enforce server-side) -- exceed it to force rejection.
    invalid_name = ctx.unique_name("sim2real-rexbadname-") + ("x" * 60)
    assert len(invalid_name) > 64, f"test name is only {len(invalid_name)} chars, need >64"

    error = _error(lambda: rex.create_view(ViewName=invalid_name))
    assert error == ("UnauthorizedException", "Unauthorized"), f"observed error={error!r}"

    # effect absent: no view exists anywhere under that rejected name
    all_view_arns: list[str] = []
    token = None
    while True:
        page = rex.list_views(**({"NextToken": token} if token else {}))
        all_view_arns.extend(page["Views"])
        token = page.get("NextToken")
        if not token:
            break
    assert not any(invalid_name in arn for arn in all_view_arns), (
        f"a view under the rejected name {invalid_name!r} is visible in ListViews: {all_view_arns!r}"
    )

    # positive control: a pattern-compliant name in the same Region succeeds
    valid_name = ctx.unique_name("sim2real-rexgoodname-")
    valid_arn = rex.create_view(ViewName=valid_name, Tags={"sim2real": CHECK})["View"]["ViewArn"]
    ctx.on_cleanup(lambda: _safe_delete(rex, valid_arn))
    got_name = rex.get_view(ViewArn=valid_arn)["View"]["ViewName"]
    assert got_name == valid_name, f"positive control: expected ViewName={valid_name!r}, got {got_name!r}"


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


def _create_index_and_wait_active(ctx, tags: dict | None = None) -> str:
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
        arn = rex.create_index(**({"Tags": tags} if tags else {}))["Arn"]

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


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
