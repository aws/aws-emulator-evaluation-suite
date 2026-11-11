"""origin-endpoint-origination-deny-blocks-playback."""
from __future__ import annotations

import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "origin-endpoint-origination-deny-blocks-playback"
GROUP = "data-plane"
SERVICES = ["mediapackage"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """With Origination=DENY, GET on the endpoint's playback Url answers 403; under ALLOW, before and after
    the toggle, it does not, so the field drives the playback data plane."""
    mp = ctx.client("mediapackage")
    channel_id = ctx.unique_name("sim2real-mp-ch-")
    mp.create_channel(Id=channel_id)
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_id))

    endpoint_id = ctx.unique_name("sim2real-mp-oe-")
    created = mp.create_origin_endpoint(Id=endpoint_id, ChannelId=channel_id, HlsPackage={})
    ctx.on_cleanup(lambda: mp.delete_origin_endpoint(Id=endpoint_id))
    url = created["Url"]
    assert created["Origination"] == "ALLOW", f"expected ALLOW on create, got {created['Origination']!r}"

    # Positive control: the data plane must be reachable (not 403) under the endpoint's
    # default ALLOW before anything is broken, so the DENY leg below proves causation
    # rather than a URL that is unconditionally 403 regardless of Origination.
    control_status = _wait_for_status(ctx, url, lambda s: s != 403, timeout_s=90.0)
    assert control_status != 403, f"expected non-403 under default ALLOW, got {control_status}"

    mp.update_origin_endpoint(Id=endpoint_id, HlsPackage={}, Origination="DENY")
    described_deny = mp.describe_origin_endpoint(Id=endpoint_id)["Origination"]
    assert described_deny == "DENY", f"expected DENY after update, got {described_deny!r}"
    deny_status = _wait_for_status(ctx, url, lambda s: s == 403, timeout_s=90.0)
    assert deny_status == 403, f"expected 403 while Origination=DENY, got {deny_status}"

    mp.update_origin_endpoint(Id=endpoint_id, HlsPackage={}, Origination="ALLOW")
    described_allow = mp.describe_origin_endpoint(Id=endpoint_id)["Origination"]
    assert described_allow == "ALLOW", f"expected ALLOW after revert, got {described_allow!r}"
    allow_status = _wait_for_status(ctx, url, lambda s: s != 403, timeout_s=90.0)
    assert allow_status != 403, f"expected non-403 after reverting to ALLOW, got {allow_status}"


def _get_status(ctx, url: str) -> int:
    target_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(target_url, method="GET", headers=route_headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except urllib.error.URLError as e:
        raise AssertionError(f"origin endpoint unreachable: {e}") from e


def _wait_for_status(ctx, url: str, predicate, timeout_s: float = 90.0, interval_s: float = 5.0) -> int:
    deadline = time.monotonic() + timeout_s
    last = _get_status(ctx, url)
    while time.monotonic() < deadline:
        if predicate(last):
            return last
        time.sleep(interval_s)
        last = _get_status(ctx, url)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
