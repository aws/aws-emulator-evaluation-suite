"""put-image-digest-mismatch-on-concurrent-push-rejected."""
from __future__ import annotations

import hashlib
import json
import re
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-image-digest-mismatch-on-concurrent-push-rejected"
GROUP = "concurrency"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Concurrent PutImage calls with a wrong imageDigest all fail with
    ImageDigestDoesNotMatchException and create no image; the same manifest with the correct
    digest succeeds."""
    ecr = ctx.client("ecr")
    repo = _ecr_name(ctx, "sim2real-digest")
    registry_id = ecr.create_repository(
        repositoryName=repo, tags=[{"Key": "sim2real", "Value": "ecr-digest-mismatch-race"}]
    )["repository"]["registryId"]
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo, force=True))

    layer_digest, layer_size = _push_test_layer(ecr, repo)
    manifest_str, correct_digest = _build_manifest(layer_digest, layer_size)
    replacement = "0" if correct_digest[-1] != "0" else "1"
    wrong_digest = correct_digest[:-1] + replacement
    assert wrong_digest != correct_digest, f"test bug: wrong_digest {wrong_digest} equals correct_digest"

    def _push(tag: str):
        try:
            resp = ecr.put_image(
                repositoryName=repo,
                imageManifest=manifest_str,
                imageDigest=wrong_digest,
                imageTag=tag,
            )
            return ("ok", resp["image"]["imageId"]["imageDigest"], None)
        except ClientError as err:
            return ("error", err.response["Error"]["Code"], err.response["Error"].get("Message"))

    tags = [f"race-{i}" for i in range(5)]
    with ThreadPoolExecutor(max_workers=5) as pool:
        outcomes = list(pool.map(_push, tags))

    assert all(kind == "error" for kind, _, _ in outcomes), f"expected all pushes rejected, got {outcomes}"
    assert all(code == "ImageDigestDoesNotMatchException" for _, code, _ in outcomes), f"wrong codes: {outcomes}"
    expected = (
        f"The image with digest '{wrong_digest}' in repository '{repo}' and registry ID '{registry_id}' "
        f"does not match the image digest that Amazon ECR has calculated."
    )
    for _, _, message in outcomes:
        assert message == expected, f"expected {expected!r}, got {message!r}"

    # None of the mismatched-digest pushes created an image under any of the race tags.
    existing_tags = {img.get("imageTag") for img in ecr.list_images(repositoryName=repo)["imageIds"]}
    assert not (existing_tags & set(tags)), f"unexpected images created: {existing_tags & set(tags)}"

    # Positive control: the SAME manifest pushed with the CORRECT digest succeeds.
    good = ecr.put_image(
        repositoryName=repo,
        imageManifest=manifest_str,
        imageDigest=correct_digest,
        imageTag="good",
    )
    assert good["image"]["imageId"]["imageDigest"] == correct_digest, (
        f"expected PutImage to accept digest {correct_digest}, got {good['image']['imageId']['imageDigest']}"
    )

    # Independent terminal read: DescribeImages (not PutImage) confirms the accepted
    # push is visible at the destination under the correct digest.
    described = ecr.describe_images(repositoryName=repo, imageIds=[{"imageTag": "good"}])["imageDetails"]
    assert len(described) == 1, f"expected exactly one described image for tag 'good', got {described}"
    assert described[0]["imageDigest"] == correct_digest, (
        f"expected DescribeImages to report digest {correct_digest} for tag 'good', got {described[0]['imageDigest']}"
    )


def _ecr_name(ctx, base: str, max_len: int = 200) -> str:
    raw = ctx.unique_name(base).lower()
    raw = re.sub(r"[^a-z0-9\-]", "-", raw)
    raw = re.sub(r"-+", "-", raw).strip("-")
    return raw[:max_len]


def _push_test_layer(ecr, repo: str):
    content = b"sim2real-ecr-behavioral-test-layer-content"
    digest = "sha256:" + hashlib.sha256(content).hexdigest()
    upload_id = ecr.initiate_layer_upload(repositoryName=repo)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(content) - 1,
        layerPartBlob=content,
    )
    ecr.complete_layer_upload(repositoryName=repo, uploadId=upload_id, layerDigests=[digest])
    return digest, len(content)


def _build_manifest(layer_digest: str, layer_size: int):
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": layer_size,
            "digest": layer_digest,
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": layer_size,
                "digest": layer_digest,
            }
        ],
    }
    manifest_str = json.dumps(manifest)
    correct_digest = "sha256:" + hashlib.sha256(manifest_str.encode()).hexdigest()
    return manifest_str, correct_digest


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
