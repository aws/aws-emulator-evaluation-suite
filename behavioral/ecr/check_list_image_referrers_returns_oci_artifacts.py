"""list-image-referrers-returns-oci-artifacts."""
from __future__ import annotations

import gzip
import hashlib
import json
import time

from behavioral_harness import tags

CHECK = "list-image-referrers-returns-oci-artifacts"
GROUP = "data-plane"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListImageReferrers returns an OCI artifact manifest that references a subject image's
    digest, with the correct artifactType and mediaType."""
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-ecr-referrer-")
    ecr.create_repository(repositoryName=repo_name, tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

    subject_digest, subject_manifest_bytes, subject_media_type = _push_minimal_image(ecr, repo_name, "subject")

    artifact_type = "application/vnd.sim2real.sbom.v1+json"
    empty_bytes = b"{}"
    empty_digest = "sha256:" + hashlib.sha256(empty_bytes).hexdigest()
    layer_bytes = b'{"sbom":"demo-payload"}'
    layer_digest = "sha256:" + hashlib.sha256(layer_bytes).hexdigest()
    _upload_blob(ecr, repo_name, empty_bytes, empty_digest)
    _upload_blob(ecr, repo_name, layer_bytes, layer_digest)

    artifact_manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": artifact_type,
        "config": {
            "mediaType": "application/vnd.oci.empty.v1+json",
            "size": len(empty_bytes),
            "digest": empty_digest,
        },
        "layers": [{"mediaType": artifact_type, "size": len(layer_bytes), "digest": layer_digest}],
        "subject": {
            "mediaType": subject_media_type,
            "size": len(subject_manifest_bytes),
            "digest": subject_digest,
        },
    }
    put_resp = ecr.put_image(
        repositoryName=repo_name,
        imageManifest=json.dumps(artifact_manifest),
        imageManifestMediaType=artifact_manifest["mediaType"],
    )
    artifact_digest = put_resp["image"]["imageId"]["imageDigest"]

    matching: list = []
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        resp = ecr.list_image_referrers(repositoryName=repo_name, subjectId={"imageDigest": subject_digest})
        matching = [r for r in resp["referrers"] if r["digest"] == artifact_digest]
        if matching:
            break
        time.sleep(5)

    assert len(matching) == 1, f"expected the pushed artifact among referrers, never appeared: {matching!r}"
    assert matching[0]["artifactType"] == artifact_type, (
        f"expected artifactType {artifact_type!r}, got {matching[0]['artifactType']!r}"
    )
    assert matching[0]["mediaType"] == artifact_manifest["mediaType"], (
        f"expected mediaType {artifact_manifest['mediaType']!r}, got {matching[0]['mediaType']!r}"
    )


def _upload_blob(ecr, repository_name: str, blob: bytes, digest: str) -> None:
    upload_id = ecr.initiate_layer_upload(repositoryName=repository_name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repository_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(blob) - 1,
        layerPartBlob=blob,
    )
    ecr.complete_layer_upload(repositoryName=repository_name, uploadId=upload_id, layerDigests=[digest])


def _push_minimal_image(ecr, repository_name: str, tag: str):
    layer_bytes = gzip.compress(b"", mtime=0)
    layer_digest = "sha256:" + hashlib.sha256(layer_bytes).hexdigest()
    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(b"").hexdigest()]},
        "history": [],
    }
    config_bytes = json.dumps(config).encode()
    config_digest = "sha256:" + hashlib.sha256(config_bytes).hexdigest()
    _upload_blob(ecr, repository_name, layer_bytes, layer_digest)
    _upload_blob(ecr, repository_name, config_bytes, config_digest)
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": len(config_bytes),
            "digest": config_digest,
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": len(layer_bytes),
                "digest": layer_digest,
            }
        ],
    }
    manifest_text = json.dumps(manifest)
    resp = ecr.put_image(
        repositoryName=repository_name,
        imageManifest=manifest_text,
        imageManifestMediaType=manifest["mediaType"],
        imageTag=tag,
    )
    digest = resp["image"]["imageId"]["imageDigest"]
    return digest, manifest_text.encode(), manifest["mediaType"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
