"""get-download-url-for-layer."""
from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


def _create_repo(ecr, ctx, name=None, **kwargs):
    """CreateRepository + register force-delete teardown; returns the repository dict."""
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    resp = ecr.create_repository(
        repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return resp["repository"]


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so a target that
    accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _http_get(ctx, url):
    """Raw HTTP GET; returns (status, body-bytes). 4xx/5xx are captured, not raised."""
    try:
        with urllib.request.urlopen(_routed_request(ctx, url), timeout=30) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()

def _sha256_digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()

def _upload_layer(ecr, repo_name, data):
    """InitiateLayerUpload -> UploadLayerPart -> CompleteLayerUpload; returns (digest, size)."""
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

def _build_manifest(layer_digest, layer_size, config_digest, config_size):
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": config_size,
            "digest": config_digest,
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": layer_size,
                "digest": layer_digest,
            }
        ],
    }
    return json.dumps(manifest)

def _push_image(ecr, repo_name, tag=None, seed=b"layer-data"):
    """Push a minimally valid Docker Schema-2 image; returns the image dict from PutImage."""
    layer_digest, layer_size = _upload_layer(ecr, repo_name, seed)
    config_seed = b'{"architecture":"amd64","config":{},"seed":"' + seed + b'"}'
    config_digest, config_size = _upload_layer(ecr, repo_name, config_seed)
    manifest_str = _build_manifest(layer_digest, layer_size, config_digest, config_size)
    kwargs = {"repositoryName": repo_name, "imageManifest": manifest_str}
    if tag:
        kwargs["imageTag"] = tag
    return ecr.put_image(**kwargs)["image"]

CHECK = "get-download-url-for-layer"
GROUP = 'image-data-plane'
SERVICES = ['ecr']

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """GetDownloadUrlForLayer returns a URL that actually serves back the exact bytes of the
    uploaded layer (an independent HTTP read at the destination, not just a URL shape), and
    refuses to mint one for a digest that was never uploaded."""
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-behav-ecr-repo-")
    _create_repo(ecr, ctx, name)
    image = _push_image(ecr, name, tag="v1", seed=b"download-content")
    layers = json.loads(image["imageManifest"])["layers"]
    layer_digest = layers[0]["digest"]

    resp = ecr.get_download_url_for_layer(repositoryName=name, layerDigest=layer_digest)
    assert resp["layerDigest"] == layer_digest, (
        f"GetDownloadUrlForLayer echoed layerDigest {resp.get('layerDigest')!r}, "
        f"expected {layer_digest!r}"
    )
    url = resp["downloadUrl"]
    assert not (p := ctx.published_url_mismatch(url)), p

    status, body = _http_get(ctx, url)
    assert status == 200, f"GET {url.split('?')[0]} returned {status}, body={body[:200]!r}"
    got_digest = _sha256_digest(body)
    assert got_digest == layer_digest, (
        f"downloaded bytes hash to {got_digest}, not the requested layer digest "
        f"{layer_digest}; the registry did not return the stored blob"
    )

    # Effect-absent negative: a well-formed digest that was never uploaded to this repo must
    # not get a URL either. An emulator that mints a URL per request (rather than per stored
    # blob) fails here.
    never_uploaded = _sha256_digest(b"sim2real-ecr-never-uploaded-blob")
    code, message = _error(
        lambda: ecr.get_download_url_for_layer(repositoryName=name, layerDigest=never_uploaded)
    )
    assert code == "LayersNotFoundException", (
        f"expected LayersNotFoundException for a digest that was never uploaded, got {code!r}"
    )
    expected = f"The layer with digest '{never_uploaded}' does not exist within the repository with name '{name}' in the registry with id '{ctx.account}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
