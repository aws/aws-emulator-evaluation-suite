"""origin-endpoint-whitelist-blocks-non-whitelisted-ip."""
from __future__ import annotations

import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "origin-endpoint-whitelist-blocks-non-whitelisted-ip"
GROUP = "overly-permissive"
SERVICES = ["mediapackage"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An OriginEndpoint whose source-IP allowlist excludes the caller's IP answers playback with 403 while
    one with no allowlist on the same channel does not, and clearing the allowlist stops the 403 on the
    same Url."""
    mp = ctx.client("mediapackage")
    channel_id = ctx.unique_name("sim2real-mp-ch-")
    mp.create_channel(Id=channel_id)
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_id))

    blocked_id = ctx.unique_name("sim2real-mp-oe-blocked-")
    blocked = mp.create_origin_endpoint(
        Id=blocked_id,
        ChannelId=channel_id,
        HlsPackage={},
        # RFC 5737 TEST-NET-3: reserved for documentation, never a real caller IP.
        Whitelist=["203.0.113.0/32"],
    )
    ctx.on_cleanup(lambda: mp.delete_origin_endpoint(Id=blocked_id))

    open_id = ctx.unique_name("sim2real-mp-oe-open-")
    opened = mp.create_origin_endpoint(Id=open_id, ChannelId=channel_id, HlsPackage={})
    ctx.on_cleanup(lambda: mp.delete_origin_endpoint(Id=open_id))

    open_status = _get_status(ctx, opened["Url"])
    assert open_status != 403, f"positive control (no allowlist on the endpoint) unexpectedly blocked: {open_status}"

    blocked_status = _wait_for_status(ctx, blocked["Url"], lambda s: s == 403, timeout_s=90.0)
    assert blocked_status == 403, f"expected 403 for a caller IP outside the allowlist, got {blocked_status}"

    mp.update_origin_endpoint(Id=blocked_id, HlsPackage={}, Whitelist=[])
    cleared = mp.describe_origin_endpoint(Id=blocked_id)["Whitelist"]
    assert cleared == [], f"expected the allowlist cleared after update, got {cleared!r}"

    restored_status = _wait_for_status(ctx, blocked["Url"], lambda s: s != 403, timeout_s=90.0)
    assert restored_status != 403, (
        f"expected the identical Url to stop returning 403 once its allowlist was cleared, "
        f"got {restored_status}"
    )


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
