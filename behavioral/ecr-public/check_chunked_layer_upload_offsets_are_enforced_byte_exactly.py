"""chunked-layer-upload-offsets-are-enforced-byte-exactly."""
from __future__ import annotations

import hashlib

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "chunked-layer-upload-offsets-are-enforced-byte-exactly"
GROUP = 'registry-data-plane'
SERVICES = ['ecr-public']

# UploadLayerPart's own size rule, measured: `LayerPartTooSmallException: All layer parts except the
# last part should be at least 5MB` is raised by CompleteLayerUpload, NOT by UploadLayerPart -- three
# 1 KB parts are accepted one by one and only the completion refuses them. So the positive leg has to
# push real 5 MiB parts for the hash-of-concatenation identity to be reachable at all.
_MIB = 1024 * 1024
_PART_BYTES = 5 * _MIB

# NOTE: every byte pushed here is synthetic and meaningless. An ECR Public repository is
# world-visible on gallery.ecr.aws for as long as it exists, so nothing real may be pushed.


def _ecr_public(ctx):
    """ECR Public is us-east-1-only (UnsupportedCommandException elsewhere), so pin the region."""
    return ctx.client("ecr-public", region="us-east-1")


def _create_repository(ctx, ecr, name=None, **kwargs):
    """CreateRepository, registering a force-delete teardown. Returns (name, response)."""
    name = name or ctx.unique_name("sim2real-behav-ecrpub-repo-")
    kwargs.setdefault("tags", [{"Key": "sim2real", "Value": CHECK}])
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return name, resp


def _error(fn) -> tuple[str, str]:
    """Call fn() and return the AWS (Error.Code, Error.Message). A call that SUCCEEDS raises."""
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"the call was expected to be refused but SUCCEEDED with {resp!r}")


def _availability(ecr, repository_name, digests):
    """BatchCheckLayerAvailability as a {digest: layerAvailability} map, asserting no failures."""
    resp = ecr.batch_check_layer_availability(
        repositoryName=repository_name, layerDigests=list(digests)
    )
    assert not resp.get("failures"), (
        f"BatchCheckLayerAvailability reported failures for {list(digests)!r}: {resp!r}"
    )
    return {lay["layerDigest"]: lay for lay in resp["layers"]}


def _synthetic(length, salt) -> bytes:
    return bytes((index * salt + 3) % 251 for index in range(length))


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """Three contiguous UploadLayerPart calls report a running lastByteReceived and complete to the
    sha256 of the concatenation; a part with a one-byte gap is InvalidLayerPartException and that
    layer stays UNAVAILABLE.
    """
    ecr = _ecr_public(ctx)
    name, _ = _create_repository(ctx, ecr)

    # --- POSITIVE: three contiguous parts, byte-exact ledger, hash of the concatenation ----------
    part_one = _synthetic(_PART_BYTES, 7)
    part_two = _synthetic(_PART_BYTES, 13)
    part_three = b"sim2real-chunked-tail-" + name.encode() + bytes(range(200))
    blob = part_one + part_two + part_three
    blob_digest = "sha256:" + hashlib.sha256(blob).hexdigest()

    initiated = ecr.initiate_layer_upload(repositoryName=name)
    upload_id = initiated["uploadId"]
    assert isinstance(initiated["partSize"], int) and initiated["partSize"] >= _PART_BYTES, (
        f"partSize {initiated.get('partSize')!r} is smaller than the 5 MiB minimum non-final part, "
        f"which would make a compliant chunked upload impossible"
    )

    offset = 0
    observed_last_bytes = []
    expected_last_bytes = []
    for part in (part_one, part_two, part_three):
        uploaded = ecr.upload_layer_part(
            repositoryName=name,
            uploadId=upload_id,
            partFirstByte=offset,
            partLastByte=offset + len(part) - 1,
            layerPartBlob=part,
        )
        offset += len(part)
        observed_last_bytes.append(uploaded["lastByteReceived"])
        expected_last_bytes.append(offset - 1)
        assert uploaded["uploadId"] == upload_id, (
            f"UploadLayerPart echoed uploadId {uploaded['uploadId']!r}, not {upload_id!r}"
        )
    assert observed_last_bytes == expected_last_bytes, (
        f"the lastByteReceived ledger read {observed_last_bytes!r}, expected the running totals "
        f"{expected_last_bytes!r}"
    )

    completed = ecr.complete_layer_upload(
        repositoryName=name, uploadId=upload_id, layerDigests=[blob_digest]
    )
    assert completed["layerDigest"] == blob_digest, (
        f"CompleteLayerUpload hashed the assembled blob to {completed['layerDigest']!r}; the sha256 "
        f"of the {len(blob)}-byte concatenation is {blob_digest!r}"
    )
    good_layer = _availability(ecr, name, [blob_digest])[blob_digest]
    assert good_layer["layerAvailability"] == "AVAILABLE", (
        f"the completed layer reads {good_layer!r}"
    )
    assert good_layer["layerSize"] == len(blob), (
        f"layerSize is {good_layer['layerSize']!r}; {len(blob)} bytes were uploaded across three "
        f"parts"
    )

    # --- NEGATIVE: a fresh upload id, one byte of gap in the second part's first byte ------------
    # Incomplete uploads have no delete operation; they expire, and repository teardown orphans
    # them.
    gapped = _synthetic(2000, 11)
    gapped_digest = "sha256:" + hashlib.sha256(gapped).hexdigest()
    gap_upload_id = ecr.initiate_layer_upload(repositoryName=name)["uploadId"]
    first = ecr.upload_layer_part(
        repositoryName=name,
        uploadId=gap_upload_id,
        partFirstByte=0,
        partLastByte=999,
        layerPartBlob=gapped[:1000],
    )
    assert first["lastByteReceived"] == 999, (
        f"the first gapped-upload part reported lastByteReceived {first['lastByteReceived']!r}, "
        f"expected 999 -- the gap below is only meaningful if the ledger starts here"
    )
    gap_code, gap_message = _error(
        lambda: ecr.upload_layer_part(
            repositoryName=name,
            uploadId=gap_upload_id,
            partFirstByte=1001,
            partLastByte=1999,
            layerPartBlob=gapped[1001:],
        )
    )
    assert gap_code == "InvalidLayerPartException", (
        f"a part starting at 1001 after a ledger at 999 was answered {gap_code!r}"
    )
    assert gap_message == "First byte of the layer part is 1001 instead of 1000", (
        f"InvalidLayerPartException message: {gap_message!r}"
    )

    # --- the effect is ABSENT: the gapped layer never entered the store --------------------------
    gapped_layer = _availability(ecr, name, [gapped_digest])[gapped_digest]
    assert gapped_layer["layerAvailability"] == "UNAVAILABLE", (
        f"the gapped layer became available anyway: {gapped_layer!r}"
    )
    assert "layerSize" not in gapped_layer, (
        f"an UNAVAILABLE layer must carry no size: {gapped_layer!r}"
    )

    # --- and the positive layer is untouched by the refusal --------------------------------------
    both = _availability(ecr, name, [blob_digest, gapped_digest])
    assert {digest: lay["layerAvailability"] for digest, lay in both.items()} == {
        blob_digest: "AVAILABLE",
        gapped_digest: "UNAVAILABLE",
    }, f"after the refusal the store reads {both!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
