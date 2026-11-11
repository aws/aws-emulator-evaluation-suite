"""batch-check-layer-availability-mixed."""
from __future__ import annotations

import hashlib
import json

from behavioral_harness import tags

def _create_repo(ecr, ctx, name=None, **kwargs):
    """CreateRepository + register force-delete teardown; returns the repository dict."""
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    resp = ecr.create_repository(
        repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return resp["repository"]

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

CHECK = "batch-check-layer-availability-mixed"
GROUP = 'image-data-plane'
SERVICES = ['ecr']

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchCheckLayerAvailability reports a real layer AVAILABLE with its exact size, and in the
    same call reports a never-uploaded digest as UNAVAILABLE or a failure, never AVAILABLE."""
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-behav-ecr-repo-")
    _create_repo(ecr, ctx, name)
    image = _push_image(ecr, name, tag="v1", seed=b"layer-check-content")
    layers = json.loads(image["imageManifest"])["layers"]
    real_digest = layers[0]["digest"]
    real_size = layers[0]["size"]
    missing_digest = "sha256:" + ("f" * 64)

    resp = ecr.batch_check_layer_availability(
        repositoryName=name, layerDigests=[real_digest, missing_digest]
    )
    by_digest = {layer["layerDigest"]: layer for layer in resp.get("layers", [])}
    assert real_digest in by_digest, f"real layer missing from response: {resp}"
    assert by_digest[real_digest]["layerAvailability"] == "AVAILABLE", (
        f"expected AVAILABLE for a real uploaded layer, got {by_digest[real_digest]!r}"
    )
    assert by_digest[real_digest]["layerSize"] == real_size, (
        f"expected layerSize {real_size} (as reported by PutImage's own manifest), "
        f"got {by_digest[real_digest]!r}"
    )

    failure_digests = {f["layerDigest"] for f in resp.get("failures", [])}
    assert by_digest.get(missing_digest, {}).get("layerAvailability") != "AVAILABLE", (
        f"bogus digest reported AVAILABLE: {resp}"
    )
    assert missing_digest in failure_digests or missing_digest in by_digest, (
        f"bogus digest silently dropped from response: {resp}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
