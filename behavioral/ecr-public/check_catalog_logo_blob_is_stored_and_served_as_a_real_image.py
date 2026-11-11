"""catalog-logo-blob-is-stored-and-served-as-a-real-image."""
from __future__ import annotations

import struct
import time
import urllib.error
import urllib.request
import zlib

from behavioral_harness import tags
from botocore.exceptions import ClientError


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "catalog-logo-blob-is-stored-and-served-as-a-real-image"
GROUP = 'catalog'
SERVICES = ['ecr-public']

# Real AWS refuses logos below a per-axis minimum somewhere in (50, 63] pixels with "Invalid image
# dimensions."; 32x32 is far enough below that boundary to be unambiguous.
_GOOD_SIDE = 64
_TOO_SMALL_SIDE = 32
_LOGO_BUDGET_S = 120.0



def _ecr_public(ctx):
    """ECR Public's API is served only in us-east-1, so the client is pinned there."""
    return ctx.client("ecr-public", region="us-east-1")


def _create_repository(ctx, ecr, name=None, **kwargs):
    """CreateRepository, registering a force-delete teardown. Returns (name, response)."""
    name = name or ctx.unique_name("sim2real-behav-ecrpub-repo-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return name, resp


def _error_code(fn) -> str:
    """Call fn() and return the AWS Error.Code; an unexpected success raises."""
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"the call was expected to be refused but SUCCEEDED with {resp!r}")


def _png(width, height, pixel):
    """A minimal valid truecolour PNG of exactly (width, height), so the IHDR of whatever comes back
    can be compared to numbers this process chose."""

    def chunk(kind, payload):
        body = kind + payload
        return (
            struct.pack(">I", len(payload))
            + body
            + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)
        )

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    scanlines = b"".join(b"\x00" + bytes(pixel) * width for _ in range(height))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(scanlines, 9))
        + chunk(b"IEND", b"")
    )


def _http_get(ctx, url):
    req = _routed_request(ctx, url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def _fetch_until_served(ctx, url):
    """GET `url` anonymously until it answers 200; raises if it never does within the budget."""
    deadline = time.time() + _LOGO_BUDGET_S
    status, headers, body = _http_get(ctx, url)
    while status != 200 and time.time() < deadline:
        time.sleep(2.0)
        status, headers, body = _http_get(ctx, url)
    assert status == 200, (
        f"the logo URL the service minted never served the asset within {_LOGO_BUDGET_S}s: "
        f"{status!r} for {url!r}"
    )
    return headers, body


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """The logoUrl minted for a PutRepositoryCatalogData logoImageBlob serves the identical PNG
    bytes; an undersized logo is refused (InvalidParameterException) leaving URL and bytes
    unchanged, and an accepted replacement gets a new URL serving the new bytes.

    Reference: https://docs.aws.amazon.com/AmazonECRPublic/latest/APIReference/API_RepositoryCatalogDataInput.html
    """
    ecr = _ecr_public(ctx)
    name, _ = _create_repository(ctx, ecr)

    good_png = _png(_GOOD_SIDE, _GOOD_SIDE, (0x10, 0x20, 0x30))
    description = f"sim2real behavioural logo round-trip for {name}"
    ecr.put_repository_catalog_data(
        repositoryName=name,
        catalogData={"logoImageBlob": good_png, "description": description},
    )

    catalog = ecr.get_repository_catalog_data(repositoryName=name)["catalogData"]
    assert "logoImageBlob" not in catalog, (
        f"logoImageBlob is an input-only member and was echoed back: {sorted(catalog)!r}"
    )
    logo_url = catalog.get("logoUrl")
    assert not (p := ctx.published_url_mismatch(logo_url)), p
    assert catalog.get("description") == description, (
        f"the description round-tripped as {catalog.get('description')!r}"
    )

    # Byte identity matters: a re-encoded or resized image would still be a valid PNG.
    headers, body = _fetch_until_served(ctx, logo_url)
    assert body == good_png, (
        f"the served asset is {len(body)} bytes; {len(good_png)} were uploaded, so the service did "
        f"not store the blob verbatim"
    )
    assert body[:8] == b"\x89PNG\r\n\x1a\n", f"the served asset is not a PNG: {body[:8]!r}"
    assert struct.unpack(">II", body[16:24]) == (_GOOD_SIDE, _GOOD_SIDE), (
        f"the served PNG's IHDR reads {struct.unpack('>II', body[16:24])!r}, not "
        f"({_GOOD_SIDE}, {_GOOD_SIDE}) -- the image was re-encoded or resized"
    )
    assert headers.get("Content-Type") == "image/png", (
        f"the asset was served as {headers.get('Content-Type')!r}"
    )

    too_small = _png(_TOO_SMALL_SIDE, _TOO_SMALL_SIDE, (0x10, 0x20, 0x30))
    assert too_small[:8] == good_png[:8], "both blobs must be valid PNGs; only the size differs"
    small_code = _error_code(
        lambda: ecr.put_repository_catalog_data(
            repositoryName=name, catalogData={"logoImageBlob": too_small}
        )
    )
    assert small_code == "InvalidParameterException", (
        f"a {_TOO_SMALL_SIDE}x{_TOO_SMALL_SIDE} logo was answered {small_code!r}"
    )

    after = ecr.get_repository_catalog_data(repositoryName=name)["catalogData"]
    assert after.get("logoUrl") == logo_url, (
        f"the refused PutRepositoryCatalogData repointed logoUrl to {after.get('logoUrl')!r}"
    )
    assert after.get("description") == description, (
        f"the refused call disturbed the description: {after.get('description')!r}"
    )
    assert "logoImageBlob" not in after, f"{sorted(after)!r}"
    _, after_body = _fetch_until_served(ctx, logo_url)
    assert after_body == good_png, (
        f"the refused logo replaced the stored asset: {len(after_body)} bytes are now served, "
        f"{len(good_png)} were accepted"
    )

    # Positive control: an accepted replacement really replaces the asset.
    replacement = _png(_GOOD_SIDE, _GOOD_SIDE, (0xFE, 0x01, 0x7F))
    assert replacement != good_png, (
        "the replacement must differ from the original in pixel content, otherwise the URL "
        "assertion below proves nothing"
    )
    ecr.put_repository_catalog_data(
        repositoryName=name, catalogData={"logoImageBlob": replacement}
    )
    replaced = ecr.get_repository_catalog_data(repositoryName=name)["catalogData"]
    assert replaced.get("logoUrl") != logo_url, (
        f"an accepted replacement reused the previous logoUrl {logo_url!r}; the two assets are "
        f"different bytes and cannot share one URL"
    )
    assert replaced.get("description") == description, (
        f"supplying only logoImageBlob wiped the description: {replaced.get('description')!r}"
    )
    _, replaced_body = _fetch_until_served(ctx, replaced["logoUrl"])
    assert replaced_body == replacement, (
        f"the new logoUrl serves {len(replaced_body)} bytes, not the {len(replacement)} that were "
        f"accepted"
    )
    assert replaced_body != good_png, (
        "the replacement URL is still serving the original asset"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
