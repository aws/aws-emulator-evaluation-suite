"""get-read-set-range-not-satisfiable-rejected."""
from __future__ import annotations

import gzip
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-read-set-range-not-satisfiable-rejected"
GROUP = "overly-permissive"
SERVICES = ["omics"]


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetReadSet rejects a partNumber beyond the read set's actual part count, while partNumber=1
    still succeeds. Real AWS reports this as ResourceNotFoundException (there is no such part on
    this read set), not RangeNotSatisfiableException."""
    omics = ctx.client("omics")
    store_id = _create_sequence_store(ctx)
    read_set_id = _create_active_read_set(ctx, store_id)

    code, message = _client_error(lambda: omics.get_read_set(sequenceStoreId=store_id, id=read_set_id, partNumber=2))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    # real AWS echoes the error code itself as the message for this refusal
    assert message == "ResourceNotFoundException", f"expected message 'ResourceNotFoundException', got {message!r}"

    # positive control: the only real part (partNumber=1) is still readable, byte-for-byte as
    # uploaded (GetReadSet returns the stored part verbatim, not decompressed)
    got = omics.get_read_set(sequenceStoreId=store_id, id=read_set_id, partNumber=1)
    body = got["payload"].read()
    decoded = gzip.decompress(body)
    assert decoded == _fastq_bytes(), f"expected {_fastq_bytes()!r} from partNumber=1, got {decoded!r}"


def _fastq_bytes() -> bytes:
    return b"@sim2real-read1\nACGTACGTAC\n+\nFFFFFFFFFF\n"


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a partNumber real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected GetReadSet to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_sequence_store(ctx) -> str:
    omics = ctx.client("omics")
    name = ctx.unique_name("sim2real-omics-seqstore-")
    store = omics.create_sequence_store(name=name, tags={"sim2real": "true"})
    store_id = store["id"]
    ctx.on_cleanup(lambda: omics.delete_sequence_store(id=store_id))
    return store_id


def _create_active_read_set(ctx, store_id: str) -> str:
    omics = ctx.client("omics")
    # real HealthOmics rejects an uncompressed FASTQ part with "File validation failed" even
    # though sourceFileType=FASTQ carries no separate gzip variant in the API.
    payload = gzip.compress(_fastq_bytes())
    upload = omics.create_multipart_read_set_upload(
        sequenceStoreId=store_id,
        sourceFileType="FASTQ",
        subjectId="sim2real-subject",
        sampleId="sim2real-sample",
        name=ctx.unique_name("sim2real-readset-"),
        tags={"sim2real": "true"},
    )
    upload_id = upload["uploadId"]
    part = omics.upload_read_set_part(
        sequenceStoreId=store_id, uploadId=upload_id, partSource="SOURCE1", partNumber=1, payload=payload,
    )
    completed = omics.complete_multipart_read_set_upload(
        sequenceStoreId=store_id,
        uploadId=upload_id,
        parts=[{"partNumber": 1, "partSource": "SOURCE1", "checksum": part["checksum"]}],
    )
    read_set_id = completed["readSetId"]

    def _cleanup():
        try:
            omics.batch_delete_read_set(ids=[read_set_id], sequenceStoreId=store_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    status = "PROCESSING_UPLOAD"
    meta = {}
    deadline = time.monotonic() + 300
    while status == "PROCESSING_UPLOAD" and time.monotonic() < deadline:
        time.sleep(5)
        meta = omics.get_read_set_metadata(sequenceStoreId=store_id, id=read_set_id)
        status = meta["status"]
    if status != "ACTIVE":
        raise AssertionError(
            f"prerequisite read set {read_set_id} ended in status {status!r}: {meta.get('statusMessage')!r}"
        )
    return read_set_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
