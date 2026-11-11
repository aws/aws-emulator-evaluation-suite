"""download-url-for-layer-expires-one-hour-after-issuance."""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.request
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse
from urllib.request import urlopen

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "download-url-for-layer-expires-one-hour-after-issuance"
GROUP = "visibility-timeout-ttl"
SERVICES = ["ecr"]

# GetDownloadUrlForLayer's presigned URL is valid for one hour.
_URL_TTL_S = 3600
# Client/server clock skew plus request latency, on each side of issuance + TTL.
_SKEW_S = 120


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """The presigned URL from GetDownloadUrlForLayer encodes an expiry one hour after issuance
    (X-Amz-Date + X-Amz-Expires, within 120 s either side) and serves the layer's exact bytes
    while valid.

    Reference: https://docs.aws.amazon.com/prescriptive-guidance/latest/presigned-url-best-practices/appendix-a.html
    """
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-ecr-ttl-")
    ecr.create_repository(repositoryName=repo_name, tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

    data = os.urandom(64)
    digest, size = _upload_blob(ecr, repo_name, data)
    manifest_bytes = _build_manifest(digest, size)
    ecr.put_image(repositoryName=repo_name, imageManifest=manifest_bytes.decode("utf-8"))

    issued_at = time.time()
    url_resp = ecr.get_download_url_for_layer(repositoryName=repo_name, layerDigest=digest)
    url = url_resp["downloadUrl"]
    assert url_resp["layerDigest"] == digest, (
        f"GetDownloadUrlForLayer echoed layerDigest {url_resp.get('layerDigest')!r}, expected {digest!r}"
    )

    expires_at = _parse_expiry(url)
    lifetime_s = expires_at - issued_at
    assert _URL_TTL_S - _SKEW_S <= lifetime_s <= _URL_TTL_S + _SKEW_S, (
        f"the presigned URL expires {lifetime_s:.0f}s after issuance, expected {_URL_TTL_S}s "
        f"(within {_SKEW_S}s either side)"
    )

    body = _http_get_bytes(ctx, url)
    got_hash, want_hash = hashlib.sha256(body).digest(), hashlib.sha256(data).digest()
    assert got_hash == want_hash, (
        f"presigned URL body hashed to {got_hash.hex()}, expected {want_hash.hex()} "
        f"(the bytes originally uploaded)"
    )


def _upload_blob(ecr, repo_name: str, data: bytes) -> tuple[str, int]:
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    upload_id = ecr.initiate_layer_upload(repositoryName=repo_name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    ecr.complete_layer_upload(
        repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest]
    )
    return digest, len(data)


def _build_manifest(digest: str, size: int) -> bytes:
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": digest,
            "size": size,
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": digest,
                "size": size,
            }
        ],
    }
    return json.dumps(manifest, separators=(",", ":")).encode("utf-8")


def _http_get_bytes(ctx, url: str) -> bytes:
    with urlopen(_routed_request(ctx, url), timeout=30) as resp:
        return resp.read()


def _parse_expiry(url: str) -> float:
    q = parse_qs(urlparse(url).query)
    amz_date = q.get("X-Amz-Date", [None])[0]
    amz_expires = q.get("X-Amz-Expires", [None])[0]
    if amz_date and amz_expires:
        dt = datetime.strptime(amz_date, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
        return dt.timestamp() + int(amz_expires)
    expires = q.get("Expires", [None])[0]
    if expires:
        return float(expires)
    raise AssertionError(
        "presigned URL has neither X-Amz-Date/X-Amz-Expires nor Expires query parameters"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
