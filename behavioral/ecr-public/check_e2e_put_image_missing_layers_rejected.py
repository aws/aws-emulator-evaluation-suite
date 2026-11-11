"""e2e-put-image-missing-layers-rejected."""
from __future__ import annotations

import hashlib
import json

from behavioral_harness import tags

CHECK = "e2e-put-image-missing-layers-rejected"
GROUP = "e2e"
SERVICES = ["ecr-public"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutImage with a manifest referencing a never-uploaded layer fails LayersNotFoundException
    and stores no image; once the layer is uploaded the same push succeeds."""
    # ecr-public is served only in us-east-1.
    ecr = ctx.client("ecr-public", region="us-east-1")
    repo_name = ctx.unique_name("sim2real-e2e-neg-repo-").lower()
    ecr.create_repository(
        repositoryName=repo_name, tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

    config_bytes = json.dumps(
        {"architecture": "amd64", "os": "linux", "config": {}, "rootfs": {"type": "layers", "diff_ids": []}}
    ).encode("utf-8")
    layer_bytes = _gzip_empty_tar()
    config_digest = _upload_blob(ecr, repo_name, config_bytes)
    real_layer_digest = "sha256:" + hashlib.sha256(layer_bytes).hexdigest()
    # Never uploaded -- a syntactically valid digest that does not exist as a layer.
    bogus_layer_digest = "sha256:" + hashlib.sha256(b"never-uploaded-layer-blob").hexdigest()

    def _manifest(layer_digest: str, layer_size: int) -> bytes:
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
                    "size": layer_size,
                    "digest": layer_digest,
                }
            ],
        }
        return json.dumps(manifest).encode("utf-8")

    bad_manifest_bytes = _manifest(bogus_layer_digest, len(layer_bytes))

    def _bad_put():
        ecr.put_image(
            repositoryName=repo_name,
            imageManifest=bad_manifest_bytes.decode("utf-8"),
            imageManifestMediaType="application/vnd.docker.distribution.manifest.v2+json",
            imageTag="broken",
        )

    code, code_msg = _error_code(_bad_put)
    assert code == "LayersNotFoundException", (
        f"PutImage must reject a manifest referencing an unuploaded layer with "
        f"LayersNotFoundException; got {code!r}"
    )
    expected_code_msg = f"Layers with digests '[{bogus_layer_digest}]' required for pushing image into repository with name '{repo_name}' in the registry with id '{ctx.account}' do not exist"
    assert code_msg == expected_code_msg, f"expected message {expected_code_msg!r}, got {code_msg!r}"

    images = ecr.describe_images(repositoryName=repo_name).get("imageDetails", [])
    assert images == [], f"the rejected PutImage created an image anyway: {images!r}"

    _upload_blob(ecr, repo_name, layer_bytes)
    good_manifest_bytes = _manifest(real_layer_digest, len(layer_bytes))
    put_resp = ecr.put_image(
        repositoryName=repo_name,
        imageManifest=good_manifest_bytes.decode("utf-8"),
        imageManifestMediaType="application/vnd.docker.distribution.manifest.v2+json",
        imageTag="good",
    )
    expected_digest = "sha256:" + hashlib.sha256(good_manifest_bytes).hexdigest()
    actual_digest = put_resp["image"]["imageId"]["imageDigest"]
    assert actual_digest == expected_digest, (
        f"PutImage's own reported digest {actual_digest!r} does not match the manifest's "
        f"recomputed digest {expected_digest!r}"
    )

    images = _poll_for_images(ecr, repo_name)
    assert len(images) == 1, (
        f"expected exactly one image in {repo_name!r} once the real layer is present, got "
        f"{len(images)}: {images!r}"
    )
    tags_on_image = images[0].get("imageTags", [])
    assert "good" in tags_on_image, (
        f"expected tag 'good' on the now-valid image, got tags {tags_on_image!r}"
    )


def _poll_for_images(ecr, repo_name: str, timeout_s: float = 30.0, interval_s: float = 2.0):
    """Poll DescribeImages, which can lag PutImage (eventual consistency)."""
    import time

    deadline = time.monotonic() + timeout_s
    images: list = []
    while time.monotonic() < deadline:
        images = ecr.describe_images(repositoryName=repo_name).get("imageDetails", [])
        if len(images) >= 1:
            return images
        time.sleep(interval_s)
    raise AssertionError(
        f"describe_images for {repo_name!r} never showed the pushed image within "
        f"{timeout_s}s; last saw {images!r}"
    )


def _error_code(fn):
    """Call fn(); return the ClientError (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _gzip_empty_tar() -> bytes:
    import gzip
    import io

    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        gz.write(b"")
    return buf.getvalue()


def _upload_blob(ecr, repo_name: str, blob: bytes) -> str:
    digest = "sha256:" + hashlib.sha256(blob).hexdigest()
    upload_id = ecr.initiate_layer_upload(repositoryName=repo_name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(blob) - 1,
        layerPartBlob=blob,
    )
    ecr.complete_layer_upload(
        repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest]
    )
    return digest


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
