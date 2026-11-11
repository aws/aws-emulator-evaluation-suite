"""upload-layer-part-streaming-then-complete."""
from __future__ import annotations

import hashlib
import os
import urllib.request

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "upload-layer-part-streaming-then-complete"
GROUP = "data-plane"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Sequential UploadLayerPart calls followed by CompleteLayerUpload reconstruct the
    full blob exactly; the reconstructed bytes are byte-for-byte retrievable via
    GetDownloadUrlForLayer."""
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-ecr-layer-")
    ecr.create_repository(repositoryName=repo_name, tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

    initiate = ecr.initiate_layer_upload(repositoryName=repo_name)
    upload_id = initiate["uploadId"]
    part_size = initiate.get("partSize") or (5 * 1024 * 1024)
    part_size = min(int(part_size), 5 * 1024 * 1024) or (5 * 1024 * 1024)

    # Two sequential parts: one full-size part, one smaller trailing part -- exercises
    # true multi-part streaming rather than a single-shot upload.
    first_part = os.urandom(part_size)
    second_part = os.urandom(max(4096, part_size // 4))
    full_content = first_part + second_part
    expected_digest = "sha256:" + hashlib.sha256(full_content).hexdigest()

    resp1 = ecr.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(first_part) - 1,
        layerPartBlob=first_part,
    )
    assert resp1["lastByteReceived"] == len(first_part) - 1, (
        f"expected lastByteReceived={len(first_part) - 1}, got {resp1['lastByteReceived']}"
    )

    resp2 = ecr.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=len(first_part),
        partLastByte=len(full_content) - 1,
        layerPartBlob=second_part,
    )
    assert resp2["lastByteReceived"] == len(full_content) - 1, (
        f"expected lastByteReceived={len(full_content) - 1}, got {resp2['lastByteReceived']}"
    )

    complete = ecr.complete_layer_upload(
        repositoryName=repo_name,
        uploadId=upload_id,
        layerDigests=[expected_digest],
    )
    assert complete["layerDigest"] == expected_digest, (
        f"expected layerDigest={expected_digest}, got {complete['layerDigest']}"
    )

    download = ecr.get_download_url_for_layer(repositoryName=repo_name, layerDigest=expected_digest)
    with urllib.request.urlopen(_routed_request(ctx, download["downloadUrl"]), timeout=60) as http_resp:
        downloaded = http_resp.read()

    assert len(downloaded) == len(full_content), "downloaded size mismatch"
    assert downloaded == full_content, "downloaded bytes do not match uploaded bytes exactly"
    downloaded_digest = "sha256:" + hashlib.sha256(downloaded).hexdigest()
    assert downloaded_digest == expected_digest, (
        f"expected digest {expected_digest}, downloaded bytes hash to {downloaded_digest}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
