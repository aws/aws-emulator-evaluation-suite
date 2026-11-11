"""put-image-rejects-manifest-with-unuploaded-layer."""
from __future__ import annotations

import hashlib
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-image-rejects-manifest-with-unuploaded-layer"
GROUP = 'image-data-plane'
SERVICES = ['ecr-public']

CONFIG_MEDIA_TYPE = "application/vnd.docker.container.image.v1+json"
LAYER_MEDIA_TYPE = "application/vnd.docker.image.rootfs.diff.tar.gzip"
MANIFEST_MEDIA_TYPE = "application/vnd.docker.distribution.manifest.v2+json"

# Every byte pushed is synthetic and meaningless: an ECR Public repository is world-visible on
# gallery.ecr.aws for as long as it exists.


def _err(fn):
    """Call fn(); return the ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_repository(ctx, ecr, name=None, **kwargs):
    """CreateRepository, registering a force-delete teardown. Returns (name, response)."""
    name = name or ctx.unique_name("sim2real-behav-ecrpub-repo-")
    resp = ecr.create_repository(
        repositoryName=name, tags=[{"Key": "sim2real", "Value": "audit"}], **kwargs
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return name, resp


def _sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _upload_blob(ecr, repository_name, data: bytes) -> str:
    """Initiate -> UploadPart -> Complete for a single blob; return its sha256 digest."""
    digest = _sha256_digest(data)
    upload_id = ecr.initiate_layer_upload(repositoryName=repository_name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repository_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    ecr.complete_layer_upload(
        repositoryName=repository_name, uploadId=upload_id, layerDigests=[digest]
    )
    return digest


def _build_manifest(config_digest, config_size, layer_digest, layer_size) -> str:
    manifest = {
        "schemaVersion": 2,
        "mediaType": MANIFEST_MEDIA_TYPE,
        "config": {"mediaType": CONFIG_MEDIA_TYPE, "size": config_size, "digest": config_digest},
        "layers": [{"mediaType": LAYER_MEDIA_TYPE, "size": layer_size, "digest": layer_digest}],
    }
    return json.dumps(manifest, separators=(",", ":"))


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutImage with a well-formed manifest whose layer was never uploaded fails with
    LayersNotFoundException and creates no image or tag; the byte-identical manifest then succeeds
    once that layer is uploaded."""
    ecr = ctx.client("ecr-public")
    name, _ = _create_repository(ctx, ecr)
    tag = "missing-layer"

    config_bytes = json.dumps({"architecture": "amd64", "os": "linux", "synthetic": True}).encode()
    layer_bytes = b"synthetic-deliberately-unuploaded-layer-" + bytes(range(48))

    # Upload the CONFIG blob only. The layer's digest is computed locally and never sent, so the
    # manifest is valid in every respect except that the registry does not hold the blob.
    config_digest = _upload_blob(ecr, name, config_bytes)
    missing_layer_digest = _sha256_digest(layer_bytes)

    availability = ecr.batch_check_layer_availability(
        repositoryName=name, layerDigests=[missing_layer_digest]
    )
    reported = {items["layerDigest"]: items["layerAvailability"] for items in availability.get("layers", [])}
    assert reported.get(missing_layer_digest) != "AVAILABLE", (
        "precondition: the layer must not be in the registry before PutImage is attempted; "
        f"BatchCheckLayerAvailability says {availability}"
    )

    manifest_str = _build_manifest(
        config_digest, len(config_bytes), missing_layer_digest, len(layer_bytes)
    )
    manifest_digest = _sha256_digest(manifest_str.encode())
    # Sanity: the manifest really does reference the missing layer, so the rejection below can
    # only be about that.
    assert missing_layer_digest in manifest_str, manifest_str

    # --- the rejection ----------------------------------------------------------------
    code, code_msg = _err(
        lambda: ecr.put_image(
            repositoryName=name,
            imageManifest=manifest_str,
            imageManifestMediaType=MANIFEST_MEDIA_TYPE,
            imageTag=tag,
        )
    )
    assert code == "LayersNotFoundException", (
        "PutImage must reject a manifest referencing a layer the registry does not hold with "
        f"LayersNotFoundException; got {code}"
    )
    expected_code_msg = f"Layers with digests '[{missing_layer_digest}]' required for pushing image into repository with name '{name}' in the registry with id '{ctx.account}' do not exist"
    assert code_msg == expected_code_msg, f"expected message {expected_code_msg!r}, got {code_msg!r}"

    # --- the effect is absent ---------------------------------------------------------
    described = ecr.describe_images(repositoryName=name)["imageDetails"]
    assert described == [], (
        f"the rejected PutImage created an image anyway: {described}"
    )
    tag_details = ecr.describe_image_tags(repositoryName=name)["imageTagDetails"]
    assert tag_details == [], (
        f"the rejected PutImage created a tag anyway: {tag_details}"
    )
    still_missing = ecr.batch_check_layer_availability(
        repositoryName=name, layerDigests=[missing_layer_digest]
    )
    still_reported = {items["layerDigest"]: items["layerAvailability"] for items in still_missing.get("layers", [])}
    assert still_reported.get(missing_layer_digest) != "AVAILABLE", (
        "PutImage must not conjure the missing layer into existence as a side effect: "
        f"{still_missing}"
    )

    # --- the control: same manifest, layer now present --------------------------------
    # Byte-identical manifest, digest and tag, so the only difference is the layer's presence.
    uploaded_digest = _upload_blob(ecr, name, layer_bytes)
    assert uploaded_digest == missing_layer_digest, (
        f"the control must upload exactly the layer the manifest names: {uploaded_digest} != "
        f"{missing_layer_digest}"
    )
    image = ecr.put_image(
        repositoryName=name,
        imageManifest=manifest_str,
        imageManifestMediaType=MANIFEST_MEDIA_TYPE,
        imageTag=tag,
    )["image"]
    assert image["imageId"]["imageDigest"] == manifest_digest, (
        image["imageId"]["imageDigest"],
        manifest_digest,
    )
    assert image["imageId"]["imageTag"] == tag, image

    final = ecr.describe_images(repositoryName=name)["imageDetails"]
    matching = [d for d in final if d["imageDigest"] == manifest_digest]
    assert len(matching) == 1, (
        f"the control PutImage did not publish the image: {[d['imageDigest'] for d in final]}"
    )
    assert tag in matching[0].get("imageTags", []), matching[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
