"""browser-lifecycle-transitions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "browser-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Browser create->CREATING->READY and DeleteBrowser fully tears down the
    underlying capacity, settling on the terminal DELETED status."""
    bac = ctx.client("bedrock-agentcore-control")
    name = _safe_name(ctx, "sim2realbrw")

    create_resp = bac.create_browser(
        name=name,
        networkConfiguration={"networkMode": "PUBLIC"},
        tags={"sim2real": CHECK},
    )
    browser_id = create_resp["browserId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: bac.delete_browser(browserId=browser_id)))

    state = _poll_until(
        lambda: _tolerant_get(lambda: bac.get_browser(browserId=browser_id)),
        lambda r: r is not None and r["status"] != "CREATING",
        timeout_s=180.0,
    )
    assert state["status"] == "READY", f"unexpected terminal status {state['status']!r}"
    assert state["name"] == name, f"expected name {name!r}, got {state['name']!r}"

    bac.delete_browser(browserId=browser_id)
    state2 = _poll_until(
        lambda: _tolerant_get(lambda: bac.get_browser(browserId=browser_id)),
        lambda r: r is None or r["status"] not in ("DELETING",),
        timeout_s=180.0,
    )
    assert state2 is None or state2["status"] == "DELETED", (
        f"unexpected terminal status {state2!r}"
    )


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
    """Newly created resources can 404 briefly before becoming visible
    (eventual consistency); treat that as "not ready yet" rather than a
    hard failure so the poll loop keeps retrying."""
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
