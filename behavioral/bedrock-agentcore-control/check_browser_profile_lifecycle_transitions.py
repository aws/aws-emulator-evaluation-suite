"""browser-profile-lifecycle-transitions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "browser-profile-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A BrowserProfile is created directly into READY (it has no CREATING
    phase) and DeleteBrowserProfile settles on the terminal DELETED status,
    all independent of an unrelated Browser instance's own lifecycle."""
    bac = ctx.client("bedrock-agentcore-control")
    profile_name = _safe_name(ctx, "sim2realprof")
    browser_name = _safe_name(ctx, "sim2realprofbr")

    profile = bac.create_browser_profile(name=profile_name, tags={"sim2real-check": CHECK})
    profile_id = profile["profileId"]
    ctx.on_cleanup(
        lambda: _safe_delete(lambda: bac.delete_browser_profile(profileId=profile_id))
    )
    assert profile["status"] == "READY"

    browser = bac.create_browser(
        name=browser_name,
        networkConfiguration={"networkMode": "PUBLIC"},
        tags={"sim2real-check": CHECK},
    )
    browser_id = browser["browserId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: bac.delete_browser(browserId=browser_id)))
    _poll_until(
        lambda: _tolerant_get(lambda: bac.get_browser(browserId=browser_id)),
        lambda r: r is not None and r["status"] != "CREATING",
        timeout_s=180.0,
    )

    bac.delete_browser_profile(profileId=profile_id)
    profile_state = _poll_until(
        lambda: _tolerant_get(lambda: bac.get_browser_profile(profileId=profile_id)),
        lambda r: r is None or r["status"] not in ("DELETING",),
        timeout_s=120.0,
    )
    assert profile_state is None or profile_state["status"] == "DELETED", (
        f"unexpected terminal status {profile_state!r}"
    )

    # The unrelated Browser instance must be untouched by the profile deletion.
    browser_state = bac.get_browser(browserId=browser_id)
    assert browser_state["status"] == "READY"


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
