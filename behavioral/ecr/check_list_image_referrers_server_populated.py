"""list-image-referrers-server-populated."""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "list-image-referrers-server-populated"
GROUP = "server-side"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutImage of an OCI artifact carrying a `subject` descriptor makes ListImageReferrers
    surface it against the subject image immediately, with no separate registration call."""
    ecr = ctx.client("ecr")
    repo = ctx.unique_name("sim2real-behav-referrers-")
    ecr.create_repository(repositoryName=repo)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo, force=True))

    empty_bytes = b"{}"
    empty_digest = _upload_blob(ctx, repo, empty_bytes)

    subj_layer_bytes = b"subject-artifact-payload-0001"
    subj_layer_digest = _upload_blob(ctx, repo, subj_layer_bytes)

    subject_manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": empty_digest,
            "size": len(empty_bytes),
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": subj_layer_digest,
                "size": len(subj_layer_bytes),
            }
        ],
    }
    subject_text = json.dumps(subject_manifest, separators=(",", ":"))
    subject_push = ecr.put_image(
        repositoryName=repo, imageManifest=subject_text, imageTag="subject"
    )
    subject_digest = subject_push["image"]["imageId"]["imageDigest"]

    ref_layer_bytes = b"sbom-artifact-payload-0002"
    ref_layer_digest = _upload_blob(ctx, repo, ref_layer_bytes)
    referrer_artifact_type = "application/vnd.sim2real.sbom.v1+json"
    referrer_manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": referrer_artifact_type,
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": empty_digest,
            "size": len(empty_bytes),
        },
        "layers": [
            {
                "mediaType": "application/vnd.sim2real.sbom.layer.v1+json",
                "digest": ref_layer_digest,
                "size": len(ref_layer_bytes),
            }
        ],
        "subject": {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": subject_digest,
            "size": len(subject_text.encode("utf-8")),
        },
    }
    referrer_text = json.dumps(referrer_manifest, separators=(",", ":"))
    # Note: no tag, and no explicit "register this as a referrer" call -- ECR must
    # derive the referrer relationship purely from the `subject` field on PutImage.
    referrer_push = ecr.put_image(repositoryName=repo, imageManifest=referrer_text)
    referrer_digest = referrer_push["image"]["imageId"]["imageDigest"]

    def fetch() -> list[dict[str, Any]]:
        return ecr.list_image_referrers(
            repositoryName=repo, subjectId={"imageDigest": subject_digest}
        ).get("referrers", [])

    referrers = _poll_until(
        fetch,
        lambda rs: any(r["digest"] == referrer_digest for r in rs),
        timeout_s=30.0,
        interval_s=2.0,
    )
    match = next(r for r in referrers if r["digest"] == referrer_digest)
    assert match["artifactType"] == referrer_artifact_type, (
        f"expected artifactType {referrer_artifact_type!r}, got {match['artifactType']!r}"
    )
    assert match["mediaType"] == "application/vnd.oci.image.manifest.v1+json", (
        f"expected mediaType application/vnd.oci.image.manifest.v1+json, got {match['mediaType']!r}"
    )
    assert match["artifactStatus"] == "ACTIVE", (
        f"expected artifactStatus ACTIVE, got {match['artifactStatus']!r}"
    )

    # A manifest pushed WITHOUT a subject field must never show up as a referrer.
    unrelated_manifest = dict(subject_manifest)
    unrelated_manifest["layers"] = [
        {
            "mediaType": "application/vnd.oci.image.layer.v1.tar",
            "digest": subj_layer_digest,
            "size": len(subj_layer_bytes),
        }
    ]
    unrelated_text = json.dumps(unrelated_manifest, separators=(",", ":"))
    unrelated_push = ecr.put_image(
        repositoryName=repo, imageManifest=unrelated_text, imageTag="unrelated"
    )
    unrelated_digest = unrelated_push["image"]["imageId"]["imageDigest"]
    still_referrers = fetch()
    assert all(r["digest"] != unrelated_digest for r in still_referrers), (
        f"a manifest pushed without a subject field appeared as a referrer: {still_referrers!r}"
    )


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


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 30.0,
    interval_s: float = 2.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    if not predicate(result):
        raise AssertionError(f"condition not met within {timeout_s}s (last: {result!r})")
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
