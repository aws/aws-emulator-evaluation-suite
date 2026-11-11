"""browser-lifecycle-and-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "browser-lifecycle-and-delete"
GROUP = "state"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateBrowser reaches READY under its name, DeleteBrowser makes it unavailable, and a second delete is refused
    with ResourceNotFoundException "Browser with ID <id> does not exist"."""
    control = ctx.client("bedrock-agentcore-control")
    name = _no_hyphen_name(ctx, "sim2realbrowser")

    create_resp = control.create_browser(
        name=name,
        networkConfiguration={"networkMode": "PUBLIC"},
        tags={"env": "sim2real-test"},
    )
    browser_id = create_resp["browserId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: control.delete_browser(browserId=browser_id)))

    final = _poll_until(
        lambda: control.get_browser(browserId=browser_id),
        lambda b: b["status"] in ("READY", "CREATE_FAILED"),
        timeout_s=120,
        interval_s=4,
    )
    assert final["status"] == "READY", f"browser ended in {final['status']!r}"
    assert final["name"] == name, f"expected name {name!r}, got {final['name']!r}"

    control.delete_browser(browserId=browser_id)
    _wait_gone(
        lambda: control.get_browser(browserId=browser_id),
        timeout_s=120,
        interval_s=4,
    )

    redelete_code, redelete_message = _error_detail(lambda: control.delete_browser(browserId=browser_id))
    assert redelete_code == "ResourceNotFoundException", (
        f"deleting an already-deleted browser returned {redelete_code!r}, "
        "expected ResourceNotFoundException"
    )
    expected_message = f"Browser with ID {browser_id} does not exist"
    assert redelete_message == expected_message, (
        f"expected message {expected_message!r}, got {redelete_message!r}"
    )


def _no_hyphen_name(ctx, prefix):
    raw = ctx.unique_name(f"{prefix}-")
    sanitized = "".join(ch for ch in raw if ch.isalnum() or ch == "_")
    return sanitized[:40]


def _error_detail(fn):
    """Return (code, message) of the ClientError fn raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _safe_delete(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "ConflictException"):
            raise


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _wait_gone(probe, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            resp = probe()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        last_status = resp.get("status")
        if last_status == "DELETED":
            return
        time.sleep(interval_s)
    raise AssertionError(f"resource did not disappear within {timeout_s}s; last status={last_status!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
