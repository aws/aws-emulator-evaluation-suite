"""delete-builtin-browser-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-builtin-browser-rejected"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteBrowser on the built-in aws.browser.v1 is refused with ResourceNotFoundException "Browser with ID
    aws.browser.v1 does not exist" and the browser stays READY, while a custom browser's delete ends gone or DELETED."""
    bac = ctx.client("bedrock-agentcore-control")

    before = bac.get_browser(browserId="aws.browser.v1")
    assert before["status"] == "READY", f"expected built-in browser READY before the test, got {before['status']!r}"

    code, message = _error_detail(lambda: bac.delete_browser(browserId="aws.browser.v1"))
    assert code == "ResourceNotFoundException", f"unexpected code {code!r}"
    expected_message = "Browser with ID aws.browser.v1 does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after = bac.get_browser(browserId="aws.browser.v1")
    assert after["status"] == "READY", f"expected built-in browser still READY after the rejected delete, got {after['status']!r}"

    # Positive control: an ordinary custom browser can be deleted.
    name = _safe_name(ctx, "sim2realbrctl")
    custom = bac.create_browser(
        name=name, networkConfiguration={"networkMode": "PUBLIC"}, tags={"sim2real": CHECK}
    )
    browser_id = custom["browserId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: bac.delete_browser(browserId=browser_id)))
    _poll_until(
        lambda: _tolerant_get(lambda: bac.get_browser(browserId=browser_id)),
        lambda r: r is not None and r["status"] != "CREATING",
        timeout_s=180.0,
    )

    bac.delete_browser(browserId=browser_id)
    state = _poll_until(
        lambda: _tolerant_get(lambda: bac.get_browser(browserId=browser_id)),
        lambda r: r is None or r["status"] not in ("DELETING",),
        timeout_s=180.0,
    )
    assert state is None or state["status"] == "DELETED", f"unexpected terminal status {state!r}"


def _error_detail(fn):
    """Return (code, message) of the ClientError fn raises; a success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _tolerant_get(fn):
    try:
        return fn()
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _safe_name(ctx, prefix):
    raw = ctx.unique_name(prefix)
    cleaned = "".join(c for c in raw if c.isalnum() or c == "_")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "a" + cleaned
    return cleaned[:48]


def _safe_delete(fn):
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
