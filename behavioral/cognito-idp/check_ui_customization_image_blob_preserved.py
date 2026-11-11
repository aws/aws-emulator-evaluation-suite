"""ui-customization-image-blob-preserved."""
from __future__ import annotations

import hashlib
import socket
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "ui-customization-image-blob-preserved"
GROUP = "representation"
SERVICES = ["cognito-idp"]

# A minimal valid 1x1 transparent PNG.
_IMAGE_BYTES = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452"
    "0000000100000001080600000"
    "01f15c489"
    "0000000d4944415478da6360000000020001"
    "e221bc33"
    "0000000049454e44ae426082"
)


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """SetUICustomization's CSS is returned unchanged by GetUICustomization with a stable ImageUrl,
    and the bytes fetched from ImageUrl match the uploaded image.
    """
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-uicustpool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-uicustclient-")
    )["UserPoolClient"]["ClientId"]

    # SetUICustomization requires a hosted-UI domain on the pool.
    domain = ctx.unique_name("sim2real-uicust").lower().replace("_", "-")
    cognito.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)
    ctx.on_cleanup(lambda: cognito.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id))
    _wait_for_domain_active(cognito, domain, timeout_s=120.0, interval_s=5.0)

    css = f".background-customizable {{ background-color: #123456; }} /* {ctx.unique_name('marker')} */"

    cognito.set_ui_customization(UserPoolId=pool_id, ClientId=client_id, CSS=css, ImageFile=_IMAGE_BYTES)

    first = cognito.get_ui_customization(UserPoolId=pool_id, ClientId=client_id)["UICustomization"]
    second = cognito.get_ui_customization(UserPoolId=pool_id, ClientId=client_id)["UICustomization"]

    assert first["CSS"] == css, "CSS content was not preserved byte-for-byte by GetUICustomization"
    assert first.get("ImageUrl"), "no ImageUrl was returned after uploading an image asset"
    assert first["ImageUrl"] == second["ImageUrl"], "ImageUrl changed between two consecutive reads of the same customization"

    expected_digest = hashlib.sha256(_IMAGE_BYTES).hexdigest()
    # Bounded retry: the image may take time to propagate to the CDN.
    fetched_bytes = _fetch_url_bytes(ctx, first["ImageUrl"], timeout_s=60.0, interval_s=5.0)
    assert hashlib.sha256(fetched_bytes).hexdigest() == expected_digest, (
        "the bytes served from ImageUrl do not match the bytes uploaded via SetUICustomization"
    )


def _wait_for_domain_active(cognito, domain: str, timeout_s: float = 120.0, interval_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = cognito.describe_user_pool_domain(Domain=domain)
        desc = resp.get("DomainDescription") or {}
        last_status = desc.get("Status")
        if last_status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"user pool domain {domain!r} did not become ACTIVE within {timeout_s}s (last status: {last_status!r})")


def _fetch_url_bytes(ctx, url: str, timeout_s: float = 60.0, interval_s: float = 5.0) -> bytes:
    deadline = time.monotonic() + timeout_s
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            _url, _route = ctx.endpoint_route(url)
            with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=10) as resp:
                return resp.read()
        except (urllib.error.URLError, socket.timeout, OSError) as exc:
            last_error = exc
            time.sleep(interval_s)
    raise AssertionError(
        f"could not fetch the hosted-UI ImageUrl within {timeout_s}s (no outbound internet access from "
        f"this environment, or CDN propagation exceeded the poll budget): {last_error!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

