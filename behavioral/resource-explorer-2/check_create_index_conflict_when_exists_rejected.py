"""create-index-conflict-when-exists-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-index-conflict-when-exists-rejected"
GROUP = "overly-permissive"
SERVICES = ["resource-explorer-2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:resource-explorer-index")
def run(ctx) -> None:
    """A second CreateIndex in a Region that already has an index is rejected with ConflictException and
    leaves that index untouched, and once it is removed the identical CreateIndex succeeds."""
    rex = ctx.client("resource-explorer-2")
    arn = _create_index_and_wait_active(ctx)

    code = _error_code(lambda: rex.create_index())
    assert code == "ConflictException", (
        f"CreateIndex while a Region index already exists must be rejected with "
        f"ConflictException; got {code!r}"
    )

    # effect absent: the original index is unaffected by the rejected duplicate create
    still_there = rex.get_index()
    assert still_there["Arn"] == arn, (
        f"the rejected duplicate CreateIndex must leave the original index untouched; expected "
        f"Arn {arn!r}, got {still_there['Arn']!r}"
    )
    assert still_there["State"] == "ACTIVE", (
        f"the rejected duplicate CreateIndex must leave the original index ACTIVE; got "
        f"{still_there['State']!r}"
    )

    # restore: once the conflicting index is gone, the identical CreateIndex call now succeeds --
    # this is what separates "rejected because one already exists" from "rejected outright".
    rex.delete_index(Arn=arn)
    _poll_index_gone(ctx)
    restored_arn = _create_index_and_wait_active(ctx)
    confirmed = rex.get_index()
    assert confirmed["Arn"] == restored_arn, (
        f"CreateIndex issued after the conflicting index was deleted must succeed and be visible "
        f"via an independent GetIndex; expected Arn {restored_arn!r}, got {confirmed['Arn']!r}"
    )
    assert confirmed["State"] == "ACTIVE", (
        f"the restored index must reach ACTIVE; got {confirmed['State']!r}"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


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
    arn = rex.create_index()["Arn"]

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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
