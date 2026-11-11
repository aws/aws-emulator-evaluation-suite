"""layer-blob-byte-equality-round-trip."""
from __future__ import annotations

import hashlib
import os

from behavioral_harness import tags

CHECK = "layer-blob-byte-equality-round-trip"
GROUP = "representation"
SERVICES = ["ecr-public"]


def _regional_client(ctx, service: str, region: str = "us-east-1"):
    """A ctx client for ``service`` pinned to ``region``: ecr-public (and CloudFormation's
    AWS::ECR::PublicRepository) is served only from us-east-1, and ctx.client keeps the
    target's endpoint, so one code path serves AWS and an emulator."""
    return ctx.client(service, region=region)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A layer uploaded across multiple UploadLayerPart calls digests to the exact SHA-256
    of the original bytes -- no truncation/corruption across the multi-part transfer."""
    ecrp = _regional_client(ctx, "ecr-public")
    name = ctx.unique_name("sim2real-behav-layer-")
    ecrp.create_repository(repositoryName=name)
    ctx.on_cleanup(lambda: ecrp.delete_repository(repositoryName=name, force=True))

    initiate = ecrp.initiate_layer_upload(repositoryName=name)
    upload_id = initiate["uploadId"]
    part_size = initiate["partSize"]
    assert part_size > 0, f"InitiateLayerUpload returned a non-positive partSize {part_size!r}"

    # First part must be exactly partSize bytes (non-final parts are size-constrained);
    # the final part is smaller and carries the remainder, forcing a real multi-part path.
    part1 = os.urandom(part_size)
    part2 = os.urandom(4096)
    full_blob = part1 + part2
    expected_digest = "sha256:" + hashlib.sha256(full_blob).hexdigest()

    up1 = ecrp.upload_layer_part(
        repositoryName=name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(part1) - 1,
        layerPartBlob=part1,
    )
    assert up1["lastByteReceived"] == len(part1) - 1, (
        f"UploadLayerPart (part 1) reported lastByteReceived {up1['lastByteReceived']!r}, "
        f"expected {len(part1) - 1}"
    )

    up2 = ecrp.upload_layer_part(
        repositoryName=name,
        uploadId=upload_id,
        partFirstByte=len(part1),
        partLastByte=len(full_blob) - 1,
        layerPartBlob=part2,
    )
    assert up2["lastByteReceived"] == len(full_blob) - 1, (
        f"UploadLayerPart (part 2) reported lastByteReceived {up2['lastByteReceived']!r}, "
        f"expected {len(full_blob) - 1}"
    )

    complete = ecrp.complete_layer_upload(
        repositoryName=name, uploadId=upload_id, layerDigests=[expected_digest]
    )
    assert complete["layerDigest"] == expected_digest, (
        f"completed layerDigest {complete['layerDigest']!r} != expected {expected_digest!r}"
    )

    avail = ecrp.batch_check_layer_availability(
        repositoryName=name, layerDigests=[expected_digest]
    )
    assert avail["failures"] == [], (
        f"BatchCheckLayerAvailability reported failures for {expected_digest!r}: {avail['failures']!r}"
    )
    assert len(avail["layers"]) == 1, (
        f"expected exactly one layer entry for {expected_digest!r}, got {avail['layers']!r}"
    )
    layer = avail["layers"][0]
    assert layer["layerDigest"] == expected_digest, (
        f"BatchCheckLayerAvailability echoed layerDigest {layer['layerDigest']!r}, expected {expected_digest!r}"
    )
    assert layer["layerAvailability"] == "AVAILABLE", (
        f"layer {expected_digest!r} reads layerAvailability {layer['layerAvailability']!r}, expected AVAILABLE"
    )
    assert layer["layerSize"] == len(full_blob), (
        f"layerSize {layer['layerSize']} != uploaded byte count {len(full_blob)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
