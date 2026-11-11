"""upload-layer-part-binary-blob-round-trip."""
from __future__ import annotations

import hashlib
import json
import os
import urllib.request
from urllib.request import urlopen

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "upload-layer-part-binary-blob-round-trip"
GROUP = "state-machine"
SERVICES = ["ecr"]

_PART1_SIZE = 5 * 1024 * 1024  # non-final parts must be >= 5 MiB
_PART2_SIZE = 1 * 1024 * 1024


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A binary layer uploaded across two UploadLayerPart calls and finalized via
    CompleteLayerUpload is retrievable byte-identical through GetDownloadUrlForLayer,
    verifying no base64/binary corruption across the multi-part upload path."""
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-ecr-binround-")
    ecr.create_repository(
        repositoryName=repo_name, tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

    part1 = os.urandom(_PART1_SIZE)
    part2 = os.urandom(_PART2_SIZE)
    full_data = part1 + part2
    digest = "sha256:" + hashlib.sha256(full_data).hexdigest()

    upload_id = ecr.initiate_layer_upload(repositoryName=repo_name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(part1) - 1,
        layerPartBlob=part1,
    )
    ecr.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=len(part1),
        partLastByte=len(full_data) - 1,
        layerPartBlob=part2,
    )
    complete_resp = ecr.complete_layer_upload(
        repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest]
    )
    assert complete_resp["layerDigest"] == digest, (
        f"CompleteLayerUpload echoed digest {complete_resp.get('layerDigest')!r}, "
        f"expected {digest!r}"
    )

    # PutImage is not required for GetDownloadUrlForLayer; it is exercised here to cover the layer
    # being part of a real pushed image rather than a bare, unreferenced blob.
    config_digest, config_size = _upload_blob(ecr, repo_name, b"{}")
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_digest,
            "size": config_size,
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": digest,
                "size": len(full_data),
            }
        ],
    }
    manifest_bytes = json.dumps(manifest, separators=(",", ":")).encode("utf-8")
    ecr.put_image(repositoryName=repo_name, imageManifest=manifest_bytes.decode("utf-8"))

    availability = ecr.batch_check_layer_availability(
        repositoryName=repo_name, layerDigests=[digest]
    )
    assert availability["layers"][0]["layerAvailability"] == "AVAILABLE", (
        f"expected AVAILABLE, got {availability['layers'][0]}"
    )
    assert availability["layers"][0]["layerSize"] == len(full_data), (
        f"layerSize {availability['layers'][0]['layerSize']} != uploaded size {len(full_data)}"
    )

    download_url = ecr.get_download_url_for_layer(
        repositoryName=repo_name, layerDigest=digest
    )["downloadUrl"]
    with urlopen(_routed_request(ctx, download_url), timeout=60) as resp:
        downloaded = resp.read()

    assert len(downloaded) == len(full_data), (
        f"downloaded size {len(downloaded)} != uploaded size {len(full_data)}"
    )
    assert hashlib.sha256(downloaded).digest() == hashlib.sha256(full_data).digest(), (
        "downloaded layer bytes do not match the uploaded binary blob"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
