"""multipart-read-set-upload-round-trip."""
from __future__ import annotations

import gzip
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "multipart-read-set-upload-round-trip"
GROUP = "data-plane"
SERVICES = ["omics"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A direct multipart read-set upload becomes ACTIVE and GetReadSet returns exactly the uploaded bytes."""
    omics = ctx.client("omics")
    store_id = _create_sequence_store(ctx)
    payload = _fastq_bytes()

    upload = omics.create_multipart_read_set_upload(
        sequenceStoreId=store_id,
        sourceFileType="FASTQ",
        subjectId="sim2real-subject",
        sampleId="sim2real-sample",
        name=ctx.unique_name("sim2real-readset-"),
    )
    upload_id = upload["uploadId"]

    part = omics.upload_read_set_part(
        sequenceStoreId=store_id,
        uploadId=upload_id,
        partSource="SOURCE1",
        partNumber=1,
        payload=payload,
    )
    checksum = part["checksum"]
    assert checksum, "upload_read_set_part did not return a checksum for the uploaded part"

    completed = omics.complete_multipart_read_set_upload(
        sequenceStoreId=store_id,
        uploadId=upload_id,
        parts=[{"partNumber": 1, "partSource": "SOURCE1", "checksum": checksum}],
    )
    read_set_id = completed["readSetId"]
    ctx.on_cleanup(lambda: _best_effort_delete(ctx, store_id, read_set_id))

    # Bounded poll for the async ingest transition; any status other than
    # PROCESSING_UPLOAD (ACTIVE or UPLOAD_FAILED) ends the loop immediately.
    metadata = {"status": "PROCESSING_UPLOAD"}
    deadline = time.monotonic() + 300
    while metadata["status"] == "PROCESSING_UPLOAD" and time.monotonic() < deadline:
        time.sleep(5)
        metadata = omics.get_read_set_metadata(sequenceStoreId=store_id, id=read_set_id)

    status = metadata["status"]
    assert status == "ACTIVE", (
        f"read set {read_set_id} ended in status {status!r}: {metadata.get('statusMessage')!r}"
    )

    got = omics.get_read_set(sequenceStoreId=store_id, id=read_set_id, partNumber=1)
    body = got["payload"].read()
    assert body == payload, "GetReadSet payload does not match the bytes that were uploaded"


def _fastq_bytes() -> bytes:
    # Omics direct-upload ingest requires gzip-compressed FASTQ; a raw-text
    # payload deterministically fails ingest with UPLOAD_FAILED.
    return gzip.compress(b"@sim2real-read1\nACGTACGTAC\n+\nFFFFFFFFFF\n")


def _create_sequence_store(ctx) -> str:
    omics = ctx.client("omics")
    name = ctx.unique_name("sim2real-omics-seqstore-")
    store = omics.create_sequence_store(name=name, tags={"sim2real": "true"})
    store_id = store["id"]
    ctx.on_cleanup(lambda: omics.delete_sequence_store(id=store_id))
    return store_id


def _best_effort_delete(ctx, store_id: str, read_set_id: str) -> None:
    try:
        ctx.client("omics").batch_delete_read_set(ids=[read_set_id], sequenceStoreId=store_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
