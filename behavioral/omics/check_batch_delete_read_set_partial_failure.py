"""batch-delete-read-set-partial-failure."""
from __future__ import annotations

import gzip
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "batch-delete-read-set-partial-failure"
GROUP = "data-plane"
SERVICES = ["omics"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchDeleteReadSet deletes the real read set and reports a per-id error for the bogus one, not vice versa."""
    omics = ctx.client("omics")
    store_id = _create_sequence_store(ctx)
    real_id = _create_active_read_set(ctx, store_id)
    bogus_id = "9" * 20  # syntactically valid (10-36 digits) but never created

    pre_delete_ids = {item["id"] for item in (omics.list_read_sets(sequenceStoreId=store_id).get("readSets") or [])}
    assert real_id in pre_delete_ids, f"ACTIVE read set {real_id} did not appear in ListReadSets before deletion"

    result = omics.batch_delete_read_set(ids=[real_id, bogus_id], sequenceStoreId=store_id)
    errored_ids = {e["id"] for e in result.get("errors", [])}

    assert bogus_id in errored_ids, "batch delete did not report an error for the nonexistent read set id"
    assert real_id not in errored_ids, "batch delete reported an error for the real read set id"

    deleted = False
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        # ListReadSets reports an empty store as {"readSets": null}, not {"readSets": []};
        # a bare ["readSets"] subscript would KeyError.
        ids_now = {item["id"] for item in (omics.list_read_sets(sequenceStoreId=store_id).get("readSets") or [])}
        if real_id not in ids_now:
            deleted = True
            break
        time.sleep(2)

    assert deleted, f"real read set {real_id} was not removed after BatchDeleteReadSet reported no error for it"

    # A deleted read set's metadata is gone outright (not a lingering DELETING/DELETED status):
    # GetReadSetMetadata raises ResourceNotFoundException.
    code, message = _client_error(lambda: omics.get_read_set_metadata(sequenceStoreId=store_id, id=real_id))
    assert code == "ResourceNotFoundException", (
        f"expected GetReadSetMetadata on the deleted read set {real_id} to raise "
        f"ResourceNotFoundException, got {code!r}"
    )
    assert message == "The specified readset does not exist.", (
        f"expected message 'The specified readset does not exist.', got {message!r}"
    )


def _client_error(fn) -> tuple[str, str]:
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _fastq_bytes() -> bytes:
    seq = "ACGTACGTAC" * 10  # 100bp, well above HealthOmics' minimum read length
    qual = "F" * len(seq)
    raw = f"@sim2real-read1\n{seq}\n+\n{qual}\n".encode()
    return gzip.compress(raw)


def _create_sequence_store(ctx) -> str:
    omics = ctx.client("omics")
    name = ctx.unique_name("sim2real-omics-seqstore-")
    store = omics.create_sequence_store(name=name, tags={"sim2real": CHECK})
    store_id = store["id"]
    ctx.on_cleanup(lambda: omics.delete_sequence_store(id=store_id))
    return store_id


def _create_active_read_set(ctx, store_id: str) -> str:
    omics = ctx.client("omics")
    payload = _fastq_bytes()
    upload = omics.create_multipart_read_set_upload(
        sequenceStoreId=store_id,
        sourceFileType="FASTQ",
        subjectId="sim2real-subject",
        sampleId="sim2real-sample",
        name=ctx.unique_name("sim2real-readset-"),
        tags={"sim2real": CHECK},
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
    metadata = {}
    deadline = time.monotonic() + 300
    while status == "PROCESSING_UPLOAD" and time.monotonic() < deadline:
        time.sleep(5)
        metadata = omics.get_read_set_metadata(sequenceStoreId=store_id, id=read_set_id)
        status = metadata["status"]
    if status != "ACTIVE":
        raise AssertionError(
            f"prerequisite read set {read_set_id} ended in status {status!r}: "
            f"{metadata.get('statusMessage', '<no statusMessage>')}"
        )
    return read_set_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
