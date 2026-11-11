"""oci-manifest-media-type-negotiation."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYER_GZIP = "application/vnd.oci.image.layer.v1.tar+gzip"
DOCKER_MANIFEST_V2 = "application/vnd.docker.distribution.manifest.v2+json"
DOCKER_CONFIG_V1 = "application/vnd.docker.container.image.v1+json"
DOCKER_LAYER_GZIP = "application/vnd.docker.image.rootfs.diff.tar.gzip"


def _repo_absent(ecr, name):
    """True once DescribeRepositories refuses `name` with RepositoryNotFoundException."""
    try:
        ecr.describe_repositories(repositoryNames=[name])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "RepositoryNotFoundException":
            return True
        raise
    return False


def _create_repo(ecr, ctx, name=None, **kwargs):
    """Create a repository with a verified force-delete teardown; returns the repository dict."""
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    resp = ecr.create_repository(
        repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs
    )
    ctx.on_cleanup(lambda: _delete_repo_verified(ecr, name))
    return resp["repository"]


def _delete_repo_verified(ecr, name, timeout_s=60):
    ecr.delete_repository(repositoryName=name, force=True)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _repo_absent(ecr, name):
            return
        time.sleep(1.0)
    raise AssertionError(f"repository {name} still present {timeout_s}s after force delete")


def _sha256_digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _upload_layer(ecr, repo_name, data):
    digest = _sha256_digest(data)
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


def _gzip_tar(entries):
    """Return (gzipped_tar_bytes, uncompressed_tar_bytes) of a deterministic rootfs layer."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        for path, payload in entries:
            info = tarfile.TarInfo(name=path)
            info.size = len(payload)
            info.mtime = 0
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(payload))
    uncompressed = raw.getvalue()
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        gz.write(uncompressed)
    return buf.getvalue(), uncompressed


CHECK = "oci-manifest-media-type-negotiation"
GROUP = 'image-data-plane'
SERVICES = ['ecr']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An OCI manifest is stored and reported as OCI and returned byte-identical to an OCI client;
    a Docker-schema-2-only client gets it converted with the same image digest and blob
    digests/sizes, while the stored bytes stay OCI."""
    ecr = ctx.client("ecr")
    repo = _create_repo(ecr, ctx)
    name = repo["repositoryName"]

    layer_gz, layer_raw = _gzip_tar([("sim2real/oci.txt", b"oci-media-type\n")])
    layer_digest, layer_size = _upload_layer(ecr, name, layer_gz)

    config = json.dumps(
        {
            "architecture": "amd64",
            "os": "linux",
            "config": {},
            "rootfs": {"type": "layers", "diff_ids": [_sha256_digest(layer_raw)]},
        }
    ).encode()
    config_digest, config_size = _upload_layer(ecr, name, config)

    manifest_str = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST,
            "config": {"mediaType": OCI_CONFIG, "size": config_size, "digest": config_digest},
            "layers": [
                {"mediaType": OCI_LAYER_GZIP, "size": layer_size, "digest": layer_digest}
            ],
            "annotations": {"org.opencontainers.image.title": "sim2real-ecr"},
        }
    )
    expected_digest = _sha256_digest(manifest_str.encode())

    tag = "oci-1"
    image = ecr.put_image(
        repositoryName=name,
        imageManifest=manifest_str,
        imageManifestMediaType=OCI_MANIFEST,
        imageTag=tag,
    )["image"]
    assert image["imageId"]["imageTag"] == tag, f"PutImage echoed {image['imageId']}"
    assert image["imageId"]["imageDigest"] == expected_digest, (
        f"PutImage assigned digest {image['imageId']['imageDigest']} but sha256 of the exact "
        f"manifest bytes we sent is {expected_digest}; the registry rewrote or re-serialised "
        f"the manifest, which changes the image's identity"
    )
    assert image["imageManifestMediaType"] == OCI_MANIFEST, (
        f"PutImage reported imageManifestMediaType {image.get('imageManifestMediaType')!r}, "
        f"expected {OCI_MANIFEST!r}"
    )

    detail = ecr.describe_images(repositoryName=name, imageIds=[{"imageTag": tag}])["imageDetails"][0]
    assert detail["imageDigest"] == expected_digest, (
        f"DescribeImages digest {detail['imageDigest']} != {expected_digest}"
    )
    assert detail["imageManifestMediaType"] == OCI_MANIFEST, (
        f"DescribeImages imageManifestMediaType is {detail.get('imageManifestMediaType')!r}, "
        f"expected {OCI_MANIFEST!r}"
    )
    # artifactMediaType is the manifest's config.mediaType.
    assert detail["artifactMediaType"] == OCI_CONFIG, (
        f"DescribeImages artifactMediaType is {detail.get('artifactMediaType')!r}, expected "
        f"{OCI_CONFIG!r} -- ECR must read it out of the manifest's config.mediaType"
    )
    # imageSizeInBytes is not asserted: whether ECR counts the config blob is not documented.

    got = ecr.batch_get_image(
        repositoryName=name, imageIds=[{"imageTag": tag}], acceptedMediaTypes=[OCI_MANIFEST]
    )
    assert got.get("failures", []) == [], f"unexpected failures: {got.get('failures')}"
    assert len(got["images"]) == 1, f"expected 1 image, got {len(got['images'])}"
    fetched = got["images"][0]
    assert fetched["imageManifest"] == manifest_str, (
        "BatchGetImage did not return the manifest byte-for-byte; stored manifests are "
        f"immutable blobs. got {fetched['imageManifest']!r}"
    )
    assert fetched["imageManifestMediaType"] == OCI_MANIFEST, (
        f"BatchGetImage imageManifestMediaType {fetched.get('imageManifestMediaType')!r} != "
        f"{OCI_MANIFEST!r}"
    )
    assert fetched["imageId"]["imageDigest"] == expected_digest, (
        f"BatchGetImage returned digest {fetched['imageId']['imageDigest']}, expected "
        f"{expected_digest}"
    )
    assert fetched["repositoryName"] == name, (
        f"BatchGetImage reported repositoryName {fetched['repositoryName']!r}, expected {name!r}"
    )

    # acceptedMediaTypes is a conversion request, not a filter: ECR converts the manifest on the
    # way out, keeping blob digests/sizes and the image digest, so the converted bytes no longer
    # hash to the digest they are returned under.
    converted_resp = ecr.batch_get_image(
        repositoryName=name,
        imageIds=[{"imageTag": tag}],
        acceptedMediaTypes=[DOCKER_MANIFEST_V2],
    )
    assert converted_resp.get("failures", []) == [], (
        f"BatchGetImage reported failures for a convertible media type: "
        f"{converted_resp.get('failures')}"
    )
    assert len(converted_resp["images"]) == 1, (
        f"expected the image to be served (converted) to a Docker-schema-2 client, got "
        f"{converted_resp.get('images')}"
    )
    converted = converted_resp["images"][0]
    assert converted["imageManifestMediaType"] == DOCKER_MANIFEST_V2, (
        f"BatchGetImage reported imageManifestMediaType "
        f"{converted.get('imageManifestMediaType')!r} for a client that accepts only "
        f"{DOCKER_MANIFEST_V2!r}; the manifest was not converted into the accepted schema"
    )
    assert converted["imageId"]["imageDigest"] == expected_digest, (
        f"the converted manifest was served under digest {converted['imageId']['imageDigest']}, "
        f"expected the stored OCI digest {expected_digest}: conversion must not change the "
        f"image's identity"
    )
    converted_doc = json.loads(converted["imageManifest"])
    assert converted_doc["mediaType"] == DOCKER_MANIFEST_V2, (
        f"converted manifest .mediaType is {converted_doc.get('mediaType')!r}, expected "
        f"{DOCKER_MANIFEST_V2!r}"
    )
    assert converted_doc["schemaVersion"] == 2, (
        f"converted manifest schemaVersion is {converted_doc.get('schemaVersion')!r}, expected 2"
    )
    assert converted_doc["config"]["mediaType"] == DOCKER_CONFIG_V1, (
        f"converted config .mediaType is {converted_doc['config'].get('mediaType')!r}, expected "
        f"{DOCKER_CONFIG_V1!r} -- the OCI config type must be rewritten, not passed through"
    )
    assert [layer["mediaType"] for layer in converted_doc["layers"]] == [DOCKER_LAYER_GZIP], (
        f"converted layer media types are "
        f"{[layer.get('mediaType') for layer in converted_doc['layers']]}, expected "
        f"[{DOCKER_LAYER_GZIP!r}]"
    )
    assert converted_doc["config"]["digest"] == config_digest, (
        f"conversion changed the config blob digest to {converted_doc['config']['digest']}, "
        f"expected {config_digest}; only the media type may be rewritten"
    )
    assert converted_doc["config"]["size"] == config_size, (
        f"conversion changed the config blob size to {converted_doc['config']['size']}, "
        f"expected {config_size}"
    )
    assert [(layer["digest"], layer["size"]) for layer in converted_doc["layers"]] == [
        (layer_digest, layer_size)
    ], (
        f"conversion changed the layer blob references: "
        f"{[(layer['digest'], layer['size']) for layer in converted_doc['layers']]}, expected "
        f"[({layer_digest!r}, {layer_size})]"
    )
    assert converted["imageManifest"] != manifest_str, (
        "BatchGetImage handed a Docker-schema-2 client the raw OCI bytes; the manifest must be "
        "converted, and an emulator that ignores acceptedMediaTypes fails here"
    )
    assert _sha256_digest(converted["imageManifest"].encode()) != expected_digest, (
        "the converted bytes hash to the stored digest, so no conversion happened"
    )

    # The conversion is per-response; the stored manifest is still the OCI bytes.
    after = ecr.batch_get_image(
        repositoryName=name, imageIds=[{"imageTag": tag}], acceptedMediaTypes=[OCI_MANIFEST]
    )["images"][0]
    assert after["imageManifest"] == manifest_str, (
        "the Docker-schema-2 fetch rewrote the STORED manifest; conversion must happen on the "
        "way out, leaving the stored blob untouched"
    )
    assert after["imageManifestMediaType"] == OCI_MANIFEST, (
        f"after the converted fetch the stored media type reads "
        f"{after.get('imageManifestMediaType')!r}, expected {OCI_MANIFEST!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
