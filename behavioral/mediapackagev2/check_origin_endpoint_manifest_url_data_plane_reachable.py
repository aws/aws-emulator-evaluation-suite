"""origin-endpoint-manifest-url-data-plane-reachable."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "origin-endpoint-manifest-url-data-plane-reachable"
GROUP = "native-protocol"
SERVICES = ["mediapackagev2"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """The HLS manifest URL of a new origin endpoint is https:// and answers 403 before a resource policy
    allows mediapackagev2:GetObject and 404 (no content ingested) after it."""
    mp = ctx.client("mediapackagev2")
    group_name = ctx.unique_name("sim2real-mpv2-grp-")
    channel_name = ctx.unique_name("sim2real-mpv2-ch-")
    endpoint_name = ctx.unique_name("sim2real-mpv2-oe-")

    mp.create_channel_group(ChannelGroupName=group_name, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))
    mp.create_channel(ChannelGroupName=group_name, ChannelName=channel_name, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name))
    created = mp.create_origin_endpoint(
        ChannelGroupName=group_name,
        ChannelName=channel_name,
        OriginEndpointName=endpoint_name,
        ContainerType="TS",
        HlsManifests=[{"ManifestName": "index"}],
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(
        lambda: mp.delete_origin_endpoint(
            ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=endpoint_name
        )
    )

    manifest_url = created["HlsManifests"][0]["Url"]
    assert manifest_url.startswith("https://"), f"unexpected manifest URL scheme: {manifest_url}"

    # A v2 OriginEndpoint has no anonymous-read grant until a resource policy explicitly
    # allows mediapackagev2:GetObject, so AWS answers 403 here, not 404.
    denied_status = _poll_for_http_status(ctx, manifest_url, timeout_s=60.0, interval_s=3.0)
    assert denied_status == 403, (
        f"expected 403 (no read policy granted yet) from {manifest_url}, got {denied_status}"
    )

    mp.put_origin_endpoint_policy(
        ChannelGroupName=group_name,
        ChannelName=channel_name,
        OriginEndpointName=endpoint_name,
        Policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "AllowPublicGetObject",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "mediapackagev2:GetObject",
                "Resource": created["Arn"],
            }],
        }),
    )

    status = _poll_for_http_status(ctx, manifest_url, timeout_s=60.0, interval_s=3.0)
    assert status == 404, f"expected 404 (no content ingested yet) from {manifest_url}, got {status}"


def _ssl_context(ctx):
    """The TLS context for this check's own call to the target, from ``ctx.http_verify``."""
    verify = ctx.http_verify
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _poll_for_http_status(ctx, published: str, *, timeout_s: float, interval_s: float) -> int:
    url = ctx.endpoint_url(published)
    deadline = time.monotonic() + timeout_s
    last_status = None
    last_error = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=10, context=_ssl_context(ctx)) as resp:
                last_status = resp.status
                return last_status
        except urllib.error.HTTPError as e:
            last_status = e.code
            return last_status
        except urllib.error.URLError as e:
            last_error = e
            time.sleep(interval_s)
    if last_status is not None:
        return last_status
    raise AssertionError(f"manifest URL {url} was never reachable: {last_error}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
