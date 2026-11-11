"""repository-catalog-data-base64-logo-round-trip."""
from __future__ import annotations

import struct
import time
import urllib.error
import urllib.request
import zlib

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "repository-catalog-data-base64-logo-round-trip"
GROUP = "server-side"
SERVICES = ["ecr-public"]
# ecr-public is served only in us-east-1 (us-west-2 returns UnsupportedCommandException).
_REGION = "us-east-1"


def _make_png(width: int, height: int, color: tuple[int, int, int]) -> bytes:
    """A minimal 8-bit RGB PNG, built without PIL.

    logoImageBlob must be a real image with both dimensions between 60 and 2048 px."""

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)  # 8-bit depth, RGB
    row = bytes(color) * width
    raw = b"".join(b"\x00" + row for _ in range(height))  # filter-type 0 per scanline
    idat = zlib.compress(raw, 9)
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


_LOGO_BYTES = _make_png(64, 64, (30, 144, 255))


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A logo blob written via PutRepositoryCatalogData is served byte-identical at the logoUrl
    GetRepositoryCatalogData returns (the response carries only the URL, so it is fetched).
    """
    ecr = ctx.client("ecr-public", region=_REGION)
    name = ctx.unique_name("sim2real-behav-ecrp-logo-")
    ecr.create_repository(repositoryName=name)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))

    ecr.put_repository_catalog_data(
        repositoryName=name,
        catalogData={"logoImageBlob": _LOGO_BYTES},
    )

    logo_url = _poll_until(
        lambda: ecr.get_repository_catalog_data(repositoryName=name)["catalogData"].get(
            "logoUrl"
        ),
        lambda url: bool(url),
        timeout_s=30,
        interval_s=2,
    )
    assert logo_url, "GetRepositoryCatalogData never surfaced a logoUrl within the deadline"

    fetched_bytes = _poll_until(
        lambda: _try_fetch(ctx, logo_url),
        lambda data: data is not None,
        timeout_s=60,
        interval_s=3,
    )
    assert fetched_bytes == _LOGO_BYTES, (
        f"logoUrl served {len(fetched_bytes) if fetched_bytes is not None else 0} bytes, "
        f"expected the {len(_LOGO_BYTES)}-byte PNG that was uploaded"
    )


def _try_fetch(ctx, url: str) -> bytes | None:
    try:
        with urllib.request.urlopen(_routed_request(ctx, url), timeout=10) as resp:  # noqa: S310
            return resp.read()
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
        return None


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
