"""upload-layer-part-binary-blob-preserved."""
from __future__ import annotations

import hashlib
import os

from behavioral_harness import tags

CHECK = "upload-layer-part-binary-blob-preserved"
GROUP = "representation"
SERVICES = ["ecr-public"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A binary layer blob uploaded across two UploadLayerPart calls (a full-size first part
    at/over the 5 MiB minimum, plus a small final part) reassembles exactly server-side,
    verified by digest match on CompleteLayerUpload and BatchCheckLayerAvailability."""
    ecrpublic = _ecrpublic(ctx)
    repo_name = ctx.unique_name("sim2real-ecrpub-blob-")

    ecrpublic.create_repository(repositoryName=repo_name)
    ctx.on_cleanup(lambda: ecrpublic.delete_repository(repositoryName=repo_name, force=True))

    init = ecrpublic.initiate_layer_upload(repositoryName=repo_name)
    upload_id = init["uploadId"]

    # Non-final parts must be >= 5 MiB (LayerPartTooSmallException otherwise); the final
    # part has no such minimum.
    part1 = os.urandom(5 * 1024 * 1024 + 1024)
    part2 = os.urandom(777)
    blob = part1 + part2
    digest = "sha256:" + hashlib.sha256(blob).hexdigest()

    r1 = ecrpublic.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(part1) - 1,
        layerPartBlob=part1,
    )
    assert r1["lastByteReceived"] == len(part1) - 1, (
        f"lastByteReceived {r1['lastByteReceived']!r} != expected {len(part1) - 1} after part 1"
    )

    r2 = ecrpublic.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=len(part1),
        partLastByte=len(blob) - 1,
        layerPartBlob=part2,
    )
    assert r2["lastByteReceived"] == len(blob) - 1, (
        f"lastByteReceived {r2['lastByteReceived']!r} != expected {len(blob) - 1} after part 2"
    )

    complete = ecrpublic.complete_layer_upload(
        repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest]
    )
    assert complete["layerDigest"] == digest, (
        f"CompleteLayerUpload returned layerDigest {complete['layerDigest']!r}, expected {digest!r}"
    )

    avail = ecrpublic.batch_check_layer_availability(repositoryName=repo_name, layerDigests=[digest])
    assert not avail["failures"], f"unexpected failures: {avail['failures']}"
    layer = avail["layers"][0]
    assert layer["layerDigest"] == digest, (
        f"BatchCheckLayerAvailability returned layerDigest {layer['layerDigest']!r}, expected {digest!r}"
    )
    assert layer["layerAvailability"] == "AVAILABLE", (
        f"layerAvailability {layer['layerAvailability']!r} != expected 'AVAILABLE'"
    )
    assert layer["layerSize"] == len(blob), f"reassembled size mismatch: {layer['layerSize']} != {len(blob)}"


def _ecrpublic(ctx):
    """ecr-public's control-plane API is served only from us-east-1, so pin that region on the
    target ctx names."""
    from botocore.config import Config

    return ctx.client("ecr-public", region="us-east-1", config=Config(retries={"max_attempts": 8, "mode": "standard"}))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
