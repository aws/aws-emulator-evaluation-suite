"""manifest-list-image-size-is-the-max-of-its-children."""
from __future__ import annotations

import hashlib
import json
import time

from behavioral_harness import tags

CHECK = "manifest-list-image-size-is-the-max-of-its-children"
GROUP = "representation"
SERVICES = ["ecr-public"]

# ImageDetail.imageSizeInBytes is documented as "If the image is a manifest list, this is the max
# size of all manifests in the list".

OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
OCI_CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"
OCI_LAYER_MEDIA_TYPE = "application/vnd.oci.image.layer.v1.tar+gzip"

# The two children are built to differ ONLY in layer length, and by a large margin, so that
# max(), sum() and len(index bytes) are three mutually distinguishable numbers. 4 KiB vs 256 KiB:
# sum is 65x the smaller, max is the larger, and the index document itself is a few hundred bytes.
_SMALL_LAYER_BYTES = 4 * 1024
_LARGE_LAYER_BYTES = 256 * 1024

# DescribeImages is read-after-write; all three digests must be visible in one response, and
# exhaustion raises.
_DESCRIBE_BUDGET_S = 60.0
_DESCRIBE_INTERVAL_S = 2.0


# Every byte pushed here is synthetic: an ECR Public repository is world-visible on
# gallery.ecr.aws for as long as it exists.


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Bounded retry that raises on exhaustion rather than returning its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} was not observed within {timeout_s}s; last read was {last!r}"
    )


def _ecr_public(ctx):
    """ECR Public's control plane is served only from us-east-1; elsewhere every operation answers
    UnsupportedCommandException, so the client is region-pinned."""
    return ctx.client("ecr-public", region="us-east-1")


def _create_repository(ctx, ecr, name=None, **kwargs):
    """CreateRepository, registering a force-delete teardown. Returns (name, response)."""
    name = name or ctx.unique_name("sim2real-behav-ecrpub-size-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return name, resp


def _sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _upload_blob(ecr, repository_name, data: bytes) -> str:
    """Initiate -> UploadPart -> Complete for one blob; return its sha256 digest."""
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


def _describe_all_images(ecr, repository_name):
    """Fully paginated DescribeImages, so a membership claim never rests on page one alone."""
    details = []
    for page in ecr.get_paginator("describe_images").paginate(repositoryName=repository_name):
        details.extend(page["imageDetails"])
    return details


def _child_manifest(config_digest, config_size, layer_digest, layer_size) -> str:
    return json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST_MEDIA_TYPE,
            "config": {
                "mediaType": OCI_CONFIG_MEDIA_TYPE,
                "size": config_size,
                "digest": config_digest,
            },
            "layers": [
                {"mediaType": OCI_LAYER_MEDIA_TYPE, "size": layer_size, "digest": layer_digest}
            ],
        },
        separators=(",", ":"),
    )


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An OCI image index's reported imageSizeInBytes is the MAX of its children's reported sizes
    -- not their sum, and not the index document's own byte length."""
    ecr = _ecr_public(ctx)
    name, _ = _create_repository(ctx, ecr)

    # --- two children differing ONLY in layer length -------------------------------------------
    # The two config documents are built to be byte-length EQUAL ("amd64" and "arm64" are both
    # five characters), so the size difference between the two children is attributable to the
    # layer alone. That makes the delta assertion independent of whether ECR Public
    # counts the config blob in imageSizeInBytes at all -- the unknown constant cancels.
    children = {}
    for arch, layer_len in (("amd64", _SMALL_LAYER_BYTES), ("arm64", _LARGE_LAYER_BYTES)):
        config_bytes = json.dumps(
            {"architecture": arch, "os": "linux", "repo": name}, separators=(",", ":")
        ).encode()
        layer_bytes = (f"sim2real-size-{arch}-".encode() * (layer_len // 20 + 1))[:layer_len]
        assert len(layer_bytes) == layer_len, (
            f"the {arch} layer was built {len(layer_bytes)} bytes long, expected {layer_len}"
        )
        config_digest = _upload_blob(ecr, name, config_bytes)
        layer_digest = _upload_blob(ecr, name, layer_bytes)
        manifest = _child_manifest(
            config_digest, len(config_bytes), layer_digest, len(layer_bytes)
        )
        digest = _sha256_digest(manifest.encode())
        pushed = ecr.put_image(
            repositoryName=name,
            imageManifest=manifest,
            imageManifestMediaType=OCI_MANIFEST_MEDIA_TYPE,
            imageDigest=digest,
        )["image"]
        assert pushed["imageId"]["imageDigest"] == digest, (
            f"the {arch} child was stored as {pushed['imageId']['imageDigest']!r}, "
            f"expected {digest!r}"
        )
        children[arch] = {
            "digest": digest,
            "manifest": manifest,
            "config_len": len(config_bytes),
            "layer_len": len(layer_bytes),
        }

    assert children["amd64"]["config_len"] == children["arm64"]["config_len"], (
        f"the two config documents must be byte-length equal for the delta assertion to hold: "
        f"{children['amd64']['config_len']} vs {children['arm64']['config_len']}"
    )

    # --- the index over both children ----------------------------------------------------------
    index_str = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": OCI_INDEX_MEDIA_TYPE,
            "manifests": [
                {
                    "mediaType": OCI_MANIFEST_MEDIA_TYPE,
                    "size": len(children[arch]["manifest"].encode()),
                    "digest": children[arch]["digest"],
                    "platform": {"architecture": arch, "os": "linux"},
                }
                for arch in sorted(children)
            ],
        },
        separators=(",", ":"),
    )
    index_digest = _sha256_digest(index_str.encode())
    index_tag = "size-index"
    pushed_index = ecr.put_image(
        repositoryName=name,
        imageManifest=index_str,
        imageManifestMediaType=OCI_INDEX_MEDIA_TYPE,
        imageTag=index_tag,
    )["image"]
    assert pushed_index["imageId"]["imageDigest"] == index_digest, (
        f"the index was stored as {pushed_index['imageId']['imageDigest']!r}, "
        f"expected {index_digest!r}"
    )

    # --- the independent read: DescribeImages, a different operation than PutImage ----------
    wanted = {index_digest} | {c["digest"] for c in children.values()}
    described = _poll_until(
        lambda: {d["imageDigest"]: d for d in _describe_all_images(ecr, name)},
        lambda by_digest: wanted <= set(by_digest),
        timeout_s=_DESCRIBE_BUDGET_S,
        interval_s=_DESCRIBE_INTERVAL_S,
        description=(
            f"DescribeImages reporting all of {sorted(wanted)} for repository {name}"
        ),
    )

    small = described[children["amd64"]["digest"]]
    large = described[children["arm64"]["digest"]]
    index = described[index_digest]
    assert index["imageManifestMediaType"] == OCI_INDEX_MEDIA_TYPE, (
        f"the index was recorded with imageManifestMediaType "
        f"{index.get('imageManifestMediaType')!r}, expected {OCI_INDEX_MEDIA_TYPE!r} -- a "
        f"registry that flattened it to a child would report a manifest media type"
    )

    small_size = small["imageSizeInBytes"]
    large_size = large["imageSizeInBytes"]
    index_size = index["imageSizeInBytes"]

    # --- the child sizes move with the layer bytes, by exactly the layer delta --------------
    layer_delta = children["arm64"]["layer_len"] - children["amd64"]["layer_len"]
    assert large_size - small_size == layer_delta, (
        f"the two children differ only by {layer_delta} layer bytes, but their reported "
        f"imageSizeInBytes differ by {large_size - small_size} "
        f"({large_size} for the {children['arm64']['layer_len']}-byte layer, {small_size} for "
        f"the {children['amd64']['layer_len']}-byte layer)"
    )
    assert small_size > 0 and large_size > small_size, (
        f"expected two distinct positive child sizes, got small={small_size} large={large_size}"
    )

    # --- the index reports the MAX of its children's reported sizes -------------------------
    # Compared against the numbers the TARGET itself reported for the children, so no size
    # literal is pinned and the rule follows the target's own accounting.
    expected_max = max(small_size, large_size)
    assert index_size == expected_max, (
        f"the index reported imageSizeInBytes {index_size}, expected max of its children's "
        f"reported sizes {expected_max} (children: {small_size}, {large_size}); sum would be "
        f"{small_size + large_size} and the index document itself is {len(index_str)} bytes"
    )
    # Stated separately so the failure message says WHICH plausible-but-wrong rule the target
    # implemented. Both comparisons can genuinely fail because the children were built unequal
    # and both far larger than the index document.
    assert index_size != small_size + large_size, (
        f"the index reported {index_size}, which is the SUM of its children "
        f"({small_size} + {large_size}); the documented rule is the max"
    )
    assert index_size != len(index_str.encode()), (
        f"the index reported {index_size}, which is the byte length of the index DOCUMENT; the "
        f"documented rule is the max of the child image sizes"
    )

    # --- DescribeImageTags agrees, field for field -------------------------------------------
    tag_details = ecr.describe_image_tags(repositoryName=name)["imageTagDetails"]
    by_tag = {t["imageTag"]: t for t in tag_details}
    assert index_tag in by_tag, (
        f"DescribeImageTags reported tags {sorted(by_tag)}, missing {index_tag!r}"
    )
    nested = by_tag[index_tag]["imageDetail"]
    assert nested["imageDigest"] == index_digest, (
        f"DescribeImageTags resolved {index_tag!r} to {nested['imageDigest']!r}, "
        f"expected {index_digest!r}"
    )
    assert nested["imageSizeInBytes"] == index_size, (
        f"DescribeImageTags reports imageSizeInBytes {nested['imageSizeInBytes']} for "
        f"{index_tag!r} while DescribeImages reports {index_size} for the same digest -- one "
        f"store must not have two answers"
    )
    assert nested["imageManifestMediaType"] == OCI_INDEX_MEDIA_TYPE, (
        f"DescribeImageTags reports imageManifestMediaType "
        f"{nested.get('imageManifestMediaType')!r} for {index_tag!r}, "
        f"expected {OCI_INDEX_MEDIA_TYPE!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
