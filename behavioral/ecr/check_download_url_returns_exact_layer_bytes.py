"""download-url-returns-exact-layer-bytes."""
from __future__ import annotations

import gzip
import hashlib
import io
import tarfile
import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


def _error_code(fn):
    """Return the ClientError code from fn(); raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_repo(ecr, ctx, name=None, **kwargs):
    """CreateRepository with a verified force-delete teardown; returns the repository dict."""
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    kwargs.setdefault("tags", [{"Key": "sim2real", "Value": CHECK}])
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: _delete_repo_verified(ecr, name))
    return resp["repository"]


def _delete_repo_verified(ecr, name, timeout_s=60):
    ecr.delete_repository(repositoryName=name, force=True)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _error_code(lambda: ecr.describe_repositories(repositoryNames=[name])) == "RepositoryNotFoundException":
            return
        time.sleep(1.0)
    raise AssertionError(f"repository {name} still present {timeout_s}s after force delete")


def _sha256_digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _upload_layer(ecr, repo_name, data):
    """Upload a single-part layer; returns (digest, size)."""
    digest = _sha256_digest(data)
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


def _gzip_tar(entries):
    """A deterministic gzip(tar) rootfs layer; returns (gzipped, uncompressed) bytes."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        for path, payload in entries:
            info = tarfile.TarInfo(name=path)
            info.size = len(payload)
            info.mtime = 0
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(payload))
    uncompressed = raw.getvalue()
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        gz.write(uncompressed)
    return buf.getvalue(), uncompressed


def _http(ctx, method, url, headers=None, data=None):
    """Raw HTTP request; returns (status, lowercased-headers, body-bytes). 4xx/5xx captured."""
    import urllib.error
    import urllib.request

    req = _routed_request(ctx, url, method=method, data=data)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as exc:
        body = exc.read() if hasattr(exc, "read") else b""
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, body

CHECK = "download-url-returns-exact-layer-bytes"
GROUP = 'image-data-plane'
SERVICES = ['ecr']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """The GetDownloadUrlForLayer URL serves the exact uploaded bytes (re-hashing to the layer
    digest), and a never-uploaded digest gets LayersNotFoundException instead of a URL."""
    ecr = ctx.client("ecr")
    repo = _create_repo(ecr, ctx)
    name = repo["repositoryName"]

    layer_gz, layer_raw = _gzip_tar([("sim2real/hello.txt", b"ecr-layer-round-trip\n")])
    digest, _size = _upload_layer(ecr, name, layer_gz)

    layers = {
        layer["layerDigest"]: layer
        for layer in ecr.batch_check_layer_availability(
            repositoryName=name, layerDigests=[digest]
        )["layers"]
    }
    assert layers[digest]["layerAvailability"] == "AVAILABLE", (
        f"uploaded layer is not AVAILABLE: {layers[digest]}"
    )
    assert layers[digest]["layerSize"] == len(layer_gz), (
        f"layerSize {layers[digest]['layerSize']} != {len(layer_gz)}"
    )

    resp = ecr.get_download_url_for_layer(repositoryName=name, layerDigest=digest)
    assert resp["layerDigest"] == digest, (
        f"GetDownloadUrlForLayer echoed layerDigest {resp.get('layerDigest')}, expected {digest}"
    )
    url = resp["downloadUrl"]
    assert not (p := ctx.published_url_mismatch(url)), p

    status, headers, body = _http(ctx, "GET", url)
    assert status == 200, f"GET {url.split('?')[0]} returned {status}, body={body[:200]!r}"
    assert len(body) == len(layer_gz), (
        f"download returned {len(body)} bytes, uploaded {len(layer_gz)}"
    )
    assert _sha256_digest(body) == digest, (
        f"downloaded bytes hash to {_sha256_digest(body)}, not the layer digest {digest}; "
        f"the registry did not return the stored blob"
    )
    with gzip.GzipFile(fileobj=io.BytesIO(body), mode="rb") as gz:
        assert gz.read() == layer_raw, "the downloaded layer does not gunzip to the uploaded tar"

    absent = _sha256_digest(b"sim2real-ecr-never-uploaded-blob")
    code = _error_code(
        lambda: ecr.get_download_url_for_layer(repositoryName=name, layerDigest=absent)
    )
    assert code == "LayersNotFoundException", (
        f"expected LayersNotFoundException for a digest that was never uploaded, got {code}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
