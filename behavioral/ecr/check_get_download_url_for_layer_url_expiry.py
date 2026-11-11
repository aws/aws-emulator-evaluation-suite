"""get-download-url-for-layer-url-expiry."""
from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "get-download-url-for-layer-url-expiry"
GROUP = "visibility-timeout-ttl"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """GetDownloadUrlForLayer returns a presigned S3 URL bounded to <=1 hour validity
    that currently serves back the exact bytes uploaded, but whose signature is
    invalidated if the signed expiry query parameter is tampered with."""
    ecr = ctx.client("ecr")
    repo = ctx.unique_name("sim2real-behav-dlurl-")
    ecr.create_repository(repositoryName=repo, tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo, force=True))

    config_bytes = b"{}"
    config_digest = _upload_blob(ctx, repo, config_bytes)
    layer_bytes = ctx.unique_name("ecr-download-url-ttl-payload-").encode("utf-8")
    layer_digest = _upload_blob(ctx, repo, layer_bytes)

    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_digest,
            "size": len(config_bytes),
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": layer_digest,
                "size": len(layer_bytes),
            }
        ],
    }
    text = json.dumps(manifest, separators=(",", ":"))
    ecr.put_image(repositoryName=repo, imageManifest=text, imageTag="ttl-check")

    resp = ecr.get_download_url_for_layer(repositoryName=repo, layerDigest=layer_digest)
    url = resp["downloadUrl"]
    assert resp["layerDigest"] == layer_digest, (
        f"GetDownloadUrlForLayer echoed layerDigest {resp.get('layerDigest')!r}, expected {layer_digest!r}"
    )

    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    if "X-Amz-Expires" in qs:
        expiry_key = "X-Amz-Expires"
        ttl = int(qs["X-Amz-Expires"][0])
        assert 0 < ttl <= 3600, f"expected <=1h presigned validity, got {ttl}s"
    elif "Expires" in qs:
        import time as _time

        expiry_key = "Expires"
        ttl = int(qs["Expires"][0]) - int(_time.time())
        assert 0 < ttl <= 3660, f"expected <=1h presigned validity, got {ttl}s"
    else:
        raise AssertionError(f"expected a presigned URL with an expiry parameter, got {parsed.query!r}")

    # The URL is valid right now and serves back exactly the bytes we uploaded.
    with urllib.request.urlopen(_routed_request(ctx, url), timeout=15) as http_resp:
        body = http_resp.read()
    assert body == layer_bytes, "downloaded layer bytes must match the bytes originally uploaded"

    # Tampering with the signed expiry query parameter invalidates the S3 signature --
    # the URL is not indefinitely valid regardless of what the query string claims.
    # Note: for SigV4 presigned URLs, X-Amz-Expires must itself be within the valid
    # 1..604800 second range or S3 rejects the request during parameter validation
    # (400) before it ever gets to checking the signature; to actually exercise the
    # "signature no longer matches" path (403) we must tamper with a value that stays
    # within the allowed bounds but differs from what was actually signed.
    tampered_qs = {k: v[0] for k, v in qs.items()}
    if expiry_key == "X-Amz-Expires":
        original_value = int(tampered_qs[expiry_key])
        tampered_qs[expiry_key] = "1" if original_value != 1 else "2"
    else:
        tampered_qs[expiry_key] = "999999"
    tampered_query = urllib.parse.urlencode(tampered_qs)
    tampered_url = parsed._replace(query=tampered_query).geturl()
    try:
        with urllib.request.urlopen(_routed_request(ctx, tampered_url), timeout=15) as http_resp2:
            status2 = http_resp2.status
    except urllib.error.HTTPError as exc:
        status2 = exc.code
    assert status2 == 403, f"expected 403 for a tampered signed URL, got {status2}"


def _upload_blob(ctx, repo: str, data: bytes) -> str:
    ecr = ctx.client("ecr")
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    upload_id = ecr.initiate_layer_upload(repositoryName=repo)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    ecr.complete_layer_upload(
        repositoryName=repo, uploadId=upload_id, layerDigests=[digest]
    )
    return digest


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
