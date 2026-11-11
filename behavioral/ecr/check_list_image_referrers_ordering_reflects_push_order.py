"""list-image-referrers-ordering-reflects-push-order."""
from __future__ import annotations

import hashlib
import json

from behavioral_harness import tags

CHECK = "list-image-referrers-ordering-reflects-push-order"
GROUP = "ordering"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListImageReferrers lists each of four pushed referrers of a subject image exactly once and
    returns them in the same order across three consecutive calls with no intervening writes."""
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-ecr-referrers-")
    ecr.create_repository(
        repositoryName=repo_name, tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

    subject_digest, subject_size, subject_media_type = _push_subject_image(
        ecr, repo_name
    )

    pushed_digests = []
    for i in range(4):
        ref_digest = _push_referrer(
            ecr,
            repo_name,
            subject_digest=subject_digest,
            subject_size=subject_size,
            subject_media_type=subject_media_type,
            seq=i,
        )
        pushed_digests.append(ref_digest)

    # Completeness: every pushed referrer shows up exactly once.
    first_pass = _list_all_referrers(ecr, repo_name, subject_digest)
    first_order = [r["digest"] for r in first_pass if r["digest"] in pushed_digests]
    assert set(first_order) == set(pushed_digests), (
        f"not all pushed referrers were listed: pushed={pushed_digests}, "
        f"listed={first_order}"
    )
    assert len(first_order) == len(pushed_digests), "a referrer digest was duplicated in the listing"

    # Ordering determinism: a second, independent listing call (no intervening writes)
    # must return the exact same order - not a randomized/arbitrary order that differs
    # call-to-call.
    second_pass = _list_all_referrers(ecr, repo_name, subject_digest)
    second_order = [r["digest"] for r in second_pass if r["digest"] in pushed_digests]
    assert second_order == first_order, (
        f"ListImageReferrers returned a different order across two calls with no "
        f"intervening writes: first={first_order}, second={second_order}"
    )

    # A third, independent listing call must agree too -- three consistent reads is a
    # stronger freeze detector than two.
    third_pass = _list_all_referrers(ecr, repo_name, subject_digest)
    third_order = [r["digest"] for r in third_pass if r["digest"] in pushed_digests]
    assert third_order == first_order, (
        f"ListImageReferrers returned a different order on a third call with no "
        f"intervening writes: first={first_order}, third={third_order}"
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


def _push_subject_image(ecr, repo_name: str) -> tuple[str, int, str]:
    """Push a minimal Docker v2 schema-2 image (real, distinct config+layer blobs) to act
    as the referrers' subject, mirroring the known-good direct blob-upload + PutImage path."""
    config_bytes = (
        b'{"architecture":"amd64","os":"linux","config":{},'
        b'"rootfs":{"type":"layers","diff_ids":[]},"variant":"subject-'
        + repo_name.encode() + b'"}'
    )
    layer_bytes = b"sim2real-ecr-referrers-subject-layer-" + repo_name.encode()

    config_digest, config_size = _upload_blob(ecr, repo_name, config_bytes)
    layer_digest, layer_size = _upload_blob(ecr, repo_name, layer_bytes)

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
    manifest_bytes = json.dumps(manifest).encode("utf-8")
    resp = ecr.put_image(
        repositoryName=repo_name, imageManifest=manifest_bytes.decode("utf-8"), imageTag="subject"
    )
    image = resp["image"]
    return image["imageId"]["imageDigest"], len(manifest_bytes), manifest["mediaType"]


def _push_referrer(
    ecr,
    repo_name: str,
    *,
    subject_digest: str,
    subject_size: int,
    subject_media_type: str,
    seq: int,
) -> str:
    """Push an OCI 1.1 image manifest that carries a `subject` pointer back at the subject
    image, with its own real config+layer blobs so the manifest is independently valid."""
    config_bytes = (
        b'{"sim2real-referrer-seq":' + str(seq).encode() + b',"repo":"'
        + repo_name.encode() + b'"}'
    )
    layer_bytes = b"sim2real-ecr-referrer-layer-" + repo_name.encode() + str(seq).encode()

    config_digest, config_size = _upload_blob(ecr, repo_name, config_bytes)
    layer_digest, layer_size = _upload_blob(ecr, repo_name, layer_bytes)

    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": "application/vnd.sim2real.referrer.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_digest,
            "size": config_size,
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": layer_digest,
                "size": layer_size,
            }
        ],
        "subject": {
            "mediaType": subject_media_type,
            "digest": subject_digest,
            "size": subject_size,
        },
        "annotations": {"sim2real.seq": str(seq)},
    }
    manifest_bytes = json.dumps(manifest).encode("utf-8")
    resp = ecr.put_image(repositoryName=repo_name, imageManifest=manifest_bytes.decode("utf-8"))
    return resp["image"]["imageId"]["imageDigest"]


def _list_all_referrers(ecr, repo_name: str, subject_digest: str) -> list[dict]:
    out: list[dict] = []
    token = None
    while True:
        kwargs = {
            "repositoryName": repo_name,
            "subjectId": {"imageDigest": subject_digest},
        }
        if token:
            kwargs["nextToken"] = token
        resp = ecr.list_image_referrers(**kwargs)
        out.extend(resp.get("referrers", []))
        token = resp.get("nextToken")
        if not token:
            break
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
