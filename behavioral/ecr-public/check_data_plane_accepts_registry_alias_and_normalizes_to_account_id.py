"""data-plane-accepts-registry-alias-and-normalizes-to-account-id."""
from __future__ import annotations

import hashlib
import json
import re

from behavioral_harness import tags

CHECK = "data-plane-accepts-registry-alias-and-normalizes-to-account-id"
GROUP = 'image-data-plane'
SERVICES = ['ecr-public']

# The model splits registryId by op:
#   the SIX data-plane ops take `registryId: RegistryIdOrAlias` (@length 2..50, NO pattern)
#     InitiateLayerUpload, UploadLayerPart, CompleteLayerUpload,
#     BatchCheckLayerAvailability, PutImage, BatchDeleteImage
#   the NINE control-plane ops take `registryId: RegistryId` (@pattern ^[0-9]{12}$)
# and every *response* field is `RegistryId`. So an alias is a legal address on the way in and
# is never a legal value on the way out.
_ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
_ALIAS_RE = re.compile(r"^[a-z][a-z0-9]+(?:[._-][a-z0-9]+)*$")

CONFIG_MEDIA_TYPE = "application/vnd.docker.container.image.v1+json"
LAYER_MEDIA_TYPE = "application/vnd.docker.image.rootfs.diff.tar.gzip"
MANIFEST_MEDIA_TYPE = "application/vnd.docker.distribution.manifest.v2+json"

# Every byte pushed here is synthetic: an ECR Public repository is world-visible on
# gallery.ecr.aws for as long as it exists.


def _create_repository(ctx, ecr, name=None, **kwargs):
    """CreateRepository, registering a force-delete teardown. Returns (name, response)."""
    name = name or ctx.unique_name("sim2real-behav-ecrpub-repo-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return name, resp


def _sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _upload_blob(ecr, repository_name, data: bytes, registry_id):
    """Initiate -> UploadPart -> Complete addressing the registry by `registry_id`.

    Returns (digest, initiate_resp, upload_resp, complete_resp).
    """
    digest = _sha256_digest(data)
    initiated = ecr.initiate_layer_upload(
        registryId=registry_id, repositoryName=repository_name
    )
    upload_id = initiated["uploadId"]
    uploaded = ecr.upload_layer_part(
        registryId=registry_id,
        repositoryName=repository_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    completed = ecr.complete_layer_upload(
        registryId=registry_id,
        repositoryName=repository_name,
        uploadId=upload_id,
        layerDigests=[digest],
    )
    return digest, initiated, uploaded, completed


def _build_manifest(config_digest, config_size, layer_digest, layer_size) -> str:
    manifest = {
        "schemaVersion": 2,
        "mediaType": MANIFEST_MEDIA_TYPE,
        "config": {"mediaType": CONFIG_MEDIA_TYPE, "size": config_size, "digest": config_digest},
        "layers": [{"mediaType": LAYER_MEDIA_TYPE, "size": layer_size, "digest": layer_digest}],
    }
    return json.dumps(manifest, separators=(",", ":"))


def _primary_alias(registry) -> str:
    primary = [a for a in registry["aliases"] if a.get("primaryRegistryAlias")]
    assert len(primary) == 1, f"expected exactly one primaryRegistryAlias, got {registry['aliases']}"
    return primary[0]["name"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """All six RegistryIdOrAlias data-plane ops accept the registry alias as registryId and answer
    with the 12-digit account id; the alias and account id address the same registry.
    """
    ecr = ctx.client("ecr-public")

    # A registry alias is provisioned lazily: on an account with no prior ECR Public activity,
    # DescribeRegistries answers `aliases: []` until the first repository exists. Create the
    # target repository before reading the alias.
    name, _ = _create_repository(ctx, ecr)
    tag = "alias-addressed"

    registries = ecr.describe_registries()["registries"]
    assert len(registries) == 1, f"an account has exactly one public registry, got {registries}"
    account = registries[0]["registryId"]
    assert _ACCOUNT_RE.match(account), f"registryId must be a 12-digit account id, got {account!r}"
    alias = _primary_alias(registries[0])
    assert _ALIAS_RE.match(alias) and 2 <= len(alias) <= 50, f"bad registry alias {alias!r}"
    assert alias != account, (
        f"the alias must not be the account id, otherwise this check proves nothing: {alias!r}"
    )

    # --- push, addressing the registry ONLY by its public alias -----------------------
    config_bytes = json.dumps({"architecture": "amd64", "os": "linux", "synthetic": True}).encode()
    layer_bytes = b"synthetic-alias-addressing-layer-" + bytes(range(64))

    config_digest, initiated, uploaded, completed = _upload_blob(
        ecr, name, config_bytes, alias
    )
    # InitiateLayerUploadResponse models ONLY {uploadId, partSize} — it is the one data-plane op
    # that does not echo the registry, so there is nothing to normalize there.
    assert set(initiated) - {"ResponseMetadata"} <= {"uploadId", "partSize"}, (
        f"InitiateLayerUploadResponse models only uploadId + partSize, got {sorted(initiated)}"
    )
    assert "registryId" not in initiated, (
        f"InitiateLayerUpload has no registryId output member; it leaked in: {initiated}"
    )
    if "partSize" in initiated:
        assert isinstance(initiated["partSize"], int) and initiated["partSize"] > 0, (
            f"partSize is the byte size of each layer part and must be positive: {initiated}"
        )

    # UploadLayerPart / CompleteLayerUpload both echo registryId, and both must echo it as a
    # RegistryId (account id), never as the alias that was sent.
    for op_name, resp in (
        ("UploadLayerPart", uploaded),
        ("CompleteLayerUpload", completed),
    ):
        assert resp.get("registryId") == account, (
            f"{op_name} was addressed by alias {alias!r} and must answer with the account id "
            f"{account}; got {resp.get('registryId')!r}"
        )
        assert resp["repositoryName"] == name, (op_name, resp)
    assert completed["layerDigest"] == config_digest, completed
    assert uploaded["uploadId"] == initiated["uploadId"], (initiated, uploaded)
    assert completed["uploadId"] == initiated["uploadId"], (initiated, completed)
    assert uploaded["lastByteReceived"] == len(config_bytes) - 1, (
        f"lastByteReceived must be the final byte index {len(config_bytes) - 1}: {uploaded}"
    )

    layer_digest, _, _, layer_completed = _upload_blob(ecr, name, layer_bytes, alias)
    assert layer_completed["layerDigest"] == layer_digest, layer_completed

    manifest_str = _build_manifest(
        config_digest, len(config_bytes), layer_digest, len(layer_bytes)
    )
    manifest_digest = _sha256_digest(manifest_str.encode())
    image = ecr.put_image(
        registryId=alias,
        repositoryName=name,
        imageManifest=manifest_str,
        imageManifestMediaType=MANIFEST_MEDIA_TYPE,
        imageTag=tag,
    )["image"]
    assert image["registryId"] == account, (
        "Image.registryId targets RegistryId (^[0-9]{12}$); an alias-addressed PutImage must "
        f"still answer with {account}, got {image['registryId']!r}"
    )
    assert _ACCOUNT_RE.match(image["registryId"]), image["registryId"]
    assert image["registryId"] != alias, image
    assert image["repositoryName"] == name, image
    assert image["imageId"]["imageTag"] == tag, image
    assert image["imageId"]["imageDigest"] == manifest_digest, (
        image["imageId"]["imageDigest"],
        manifest_digest,
    )

    # --- the alias and the account id resolve to the SAME registry --------------------
    by_alias = ecr.batch_check_layer_availability(
        registryId=alias, repositoryName=name, layerDigests=[layer_digest, config_digest]
    )
    assert not by_alias.get("failures"), (
        f"BatchCheckLayerAvailability by alias reported failures for layers it stores: {by_alias}"
    )
    availability = {items["layerDigest"]: items for items in by_alias["layers"]}
    assert set(availability) == {layer_digest, config_digest}, (
        f"both uploaded layers must be reported, got {sorted(availability)}"
    )
    assert availability[layer_digest]["layerAvailability"] == "AVAILABLE", availability[layer_digest]
    assert availability[layer_digest]["layerSize"] == len(layer_bytes), (
        f"layerSize must be the uploaded byte count {len(layer_bytes)}: {availability[layer_digest]}"
    )
    assert availability[config_digest]["layerAvailability"] == "AVAILABLE", availability[config_digest]

    by_account = ecr.batch_check_layer_availability(
        registryId=account, repositoryName=name, layerDigests=[layer_digest, config_digest]
    )
    assert not by_account.get("failures"), by_account
    assert {items["layerDigest"]: items["layerAvailability"] for items in by_account["layers"]} == {
        d: "AVAILABLE" for d in (layer_digest, config_digest)
    }, (
        "the alias and the account id must address one registry, not two: "
        f"by-alias={by_alias['layers']} by-account={by_account['layers']}"
    )

    # The image pushed via the alias is visible through the account-scoped control plane.
    details = ecr.describe_images(registryId=account, repositoryName=name)["imageDetails"]
    matching = [d for d in details if d["imageDigest"] == manifest_digest]
    assert len(matching) == 1, (
        f"the alias-pushed image must be visible account-scoped; digests={[d['imageDigest'] for d in details]}"
    )
    assert matching[0]["registryId"] == account, matching[0]
    assert tag in matching[0].get("imageTags", []), matching[0]

    # --- BatchDeleteImage, also alias-addressed --------------------------------------
    deleted = ecr.batch_delete_image(
        registryId=alias, repositoryName=name, imageIds=[{"imageDigest": manifest_digest}]
    )
    assert not deleted.get("failures"), f"alias-addressed BatchDeleteImage failed: {deleted}"
    assert [i["imageDigest"] for i in deleted["imageIds"]] == [manifest_digest], deleted

    remaining = ecr.describe_images(registryId=account, repositoryName=name)["imageDetails"]
    assert all(d["imageDigest"] != manifest_digest for d in remaining), (
        f"the image survived an alias-addressed delete: {remaining}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
