"""catalog-logo-blob-is-input-only-and-size-capped."""
from __future__ import annotations

import struct
import time
import zlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "catalog-logo-blob-is-input-only-and-size-capped"
GROUP = 'catalog-data'
SERVICES = ['ecr-public']

# logoImageBlob (input-only, max 512000 bytes) becomes logoUrl (output-only, max 2048 chars).
_LOGO_MAX = 512000
_LOGO_URL_MAX = 2048

# Beyond the modelled length cap, the service enforces a 60x60-pixel minimum in both axes
# (no Smithy trait); there is no upper dimension bound near the byte cap.
_LOGO_MIN_PX = 60
# Valid images sit above the floor so length assertions never become dimension assertions.
_LOGO_PX = 64


def _err(fn):
    """Call fn(), which must fail; return its (Error.Code, Error.Message). A success raises.

    Over-long and under-sized logos share a code and differ only in message.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_repository(ctx, ecr, name=None, **kwargs):
    """CreateRepository, registering a force-delete teardown. Returns (name, response)."""
    name = name or ctx.unique_name("sim2real-behav-ecrpub-repo-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return name, resp


def _poll(fn, timeout_s=60, interval_s=2):
    """Call fn() until it returns a truthy value; return it, or None at the deadline."""
    deadline = time.time() + timeout_s
    result = None
    while time.time() < deadline:
        result = fn()
        if result:
            return result
        time.sleep(interval_s)
    return result


def _catalog_once_logo_present(ecr, name):
    """The repository's catalog data, but only once a logoUrl has appeared; else None."""
    data = ecr.get_repository_catalog_data(repositoryName=name)["catalogData"]
    return data if data.get("logoUrl") else None


def _chunk(kind: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + kind
        + data
        + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    )


def _synthetic_png(total_size: int, width: int = _LOGO_PX, height: int = _LOGO_PX) -> bytes:
    """A valid `width` x `height` greyscale PNG of exactly `total_size` bytes, padded via `tEXt`.

    A real PNG because the service decodes the image; content is synthetic as it is published.
    """
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = _chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0))
    # One filter byte (0 = None) then `width` samples, per scanline.
    idat = _chunk(b"IDAT", zlib.compress((b"\x00" + b"\x80" * width) * height, 9))
    iend = _chunk(b"IEND", b"")
    base = sig + ihdr + idat + iend
    if total_size <= len(base):
        return base
    keyword = b"Comment"
    pad = total_size - len(base) - (12 + len(keyword) + 1)
    assert pad >= 0, f"cannot build a {total_size}-byte PNG; the floor is {len(base) + 20}"
    text = (b"SIM2REAL-SYNTHETIC-PADDING-" * (pad // 27 + 1))[:pad]
    return sig + ihdr + _chunk(b"tEXt", keyword + b"\x00" + text) + idat + iend


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """logoImageBlob comes back only as a https logoUrl, never echoed; a blob one byte past 512000
    and a 59x60 image are each rejected with InvalidParameterException leaving the catalog intact.

    Reference: https://docs.aws.amazon.com/AmazonECRPublic/latest/APIReference/API_RepositoryCatalogDataInput.html
    """
    ecr = ctx.client("ecr-public")
    name, _ = _create_repository(ctx, ecr)

    baseline_desc = "SIM2REAL-SYNTHETIC-TEST-DATA-logo-case"
    logo = _synthetic_png(1024)
    assert len(logo) == 1024

    put = ecr.put_repository_catalog_data(
        repositoryName=name,
        catalogData={"description": baseline_desc, "logoImageBlob": logo},
    )
    assert "logoImageBlob" not in put["catalogData"], (
        "logoImageBlob is an INPUT-only member of RepositoryCatalogDataInput; "
        "RepositoryCatalogData does not model it and PutRepositoryCatalogData must not echo the "
        f"bytes back. Got members {sorted(put['catalogData'])}"
    )
    # The blob -> URL transform is synchronous: the Put response already carries logoUrl.
    assert put["catalogData"].get("logoUrl"), (
        "PutRepositoryCatalogData must return the minted logoUrl in its own response, got members "
        f"{sorted(put['catalogData'])}"
    )

    # Polled in case the Get side is eventually consistent; the deadline is the assertion.
    stored = _poll(lambda: _catalog_once_logo_present(ecr, name))
    assert stored is not None and stored.get("logoUrl"), (
        "after a successful logoImageBlob upload the catalog data must expose a logoUrl; none "
        f"appeared within the deadline: {ecr.get_repository_catalog_data(repositoryName=name)}"
    )
    logo_url = stored["logoUrl"]
    assert isinstance(logo_url, str) and len(logo_url) <= _LOGO_URL_MAX, (
        f"logoUrl must be a string within {_LOGO_URL_MAX} characters, got {len(logo_url)}"
    )
    assert logo_url.startswith("https://"), (
        f"a publicly served Gallery logo URL must be https, got {logo_url!r}"
    )
    assert "logoImageBlob" not in stored, (
        f"GetRepositoryCatalogData must not return the raw blob: {sorted(stored)}"
    )
    assert stored.get("description") == baseline_desc, stored

    oversized = _synthetic_png(_LOGO_MAX + 1)
    assert len(oversized) == _LOGO_MAX + 1
    code, message = _err(
        lambda: ecr.put_repository_catalog_data(
            repositoryName=name,
            catalogData={"description": "SIM2REAL-SYNTHETIC-oversized-logo", "logoImageBlob": oversized},
        )
    )
    assert code == "InvalidParameterException", (
        f"a {_LOGO_MAX + 1}-byte logoImageBlob is one past the @length max {_LOGO_MAX} and must be "
        f"rejected with InvalidParameterException; got {code}"
    )
    assert message == (
        "Invalid parameter at 'catalogData.logoImageBlob' failed to satisfy constraint: "
        f"'Member must have length less than or equal to {_LOGO_MAX}'"
    ), f"the over-limit refusal must state the {_LOGO_MAX}-byte maximum, got {message!r}"
    after = ecr.get_repository_catalog_data(repositoryName=name)["catalogData"]
    assert after.get("description") == baseline_desc, (
        f"the rejected over-limit write mutated the description: {after.get('description')!r}"
    )
    assert after.get("logoUrl") == logo_url, (
        f"the rejected over-limit write replaced the stored logo: {after.get('logoUrl')!r} != {logo_url!r}"
    )
    assert "logoImageBlob" not in after, sorted(after)

    # Well inside the byte cap, so only its pixel size is wrong.
    undersized = _synthetic_png(1024, width=_LOGO_MIN_PX - 1, height=_LOGO_MIN_PX)
    assert len(undersized) == 1024
    dim_code, dim_message = _err(
        lambda: ecr.put_repository_catalog_data(
            repositoryName=name,
            catalogData={"description": "SIM2REAL-SYNTHETIC-undersized-logo", "logoImageBlob": undersized},
        )
    )
    assert dim_code == "InvalidParameterException", (
        f"a {_LOGO_MIN_PX - 1}x{_LOGO_MIN_PX} logo is below the {_LOGO_MIN_PX}x{_LOGO_MIN_PX} "
        f"minimum and must be rejected with InvalidParameterException; got {dim_code}"
    )
    assert dim_message == (
        "Invalid parameter at 'logoImageBlob' failed to satisfy constraint: "
        "'Invalid image dimensions.'"
    ), f"the refusal must name image dimensions as the failed constraint, got {dim_message!r}"
    assert str(_LOGO_MAX) not in dim_message, (
        "the dimension refusal must not be the length refusal in disguise; the two constraints are "
        f"distinct: {dim_message!r}"
    )
    after_dim = ecr.get_repository_catalog_data(repositoryName=name)["catalogData"]
    assert after_dim.get("logoUrl") == logo_url, (
        f"the rejected under-sized write replaced the stored logo: {after_dim.get('logoUrl')!r}"
    )
    assert after_dim.get("description") == baseline_desc, (
        f"the rejected under-sized write mutated the description: {after_dim.get('description')!r}"
    )

    # Control: an in-limit blob still succeeds.
    replacement = _synthetic_png(2048)
    control = ecr.put_repository_catalog_data(
        repositoryName=name,
        catalogData={"description": baseline_desc, "logoImageBlob": replacement},
    )
    assert "logoImageBlob" not in control["catalogData"], sorted(control["catalogData"])
    final = _poll(lambda: _catalog_once_logo_present(ecr, name))
    assert final is not None and final.get("logoUrl"), (
        f"the control in-limit logo upload produced no logoUrl: {final}"
    )
    assert final.get("description") == baseline_desc, final


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
