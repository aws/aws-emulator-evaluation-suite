"""delete-sequence-store-with-active-read-set-conflict-rejected."""
from __future__ import annotations

import gzip
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-sequence-store-with-active-read-set-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["omics"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteSequenceStore is rejected while it still contains a read set; it succeeds once the read set is gone."""
    omics = ctx.client("omics")
    store_id = _create_sequence_store(ctx)
    read_set_id = _create_active_read_set(ctx, store_id)

    code, message = _client_error(lambda: omics.delete_sequence_store(id=store_id))
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected = "The specified resource is associated with other resources and cannot be deleted."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: both the store and the read set are untouched
    store_status = omics.get_sequence_store(id=store_id)["status"]
    assert store_status == "ACTIVE", f"expected sequence store to remain ACTIVE, got {store_status!r}"
    read_set_status = omics.get_read_set_metadata(sequenceStoreId=store_id, id=read_set_id)["status"]
    assert read_set_status == "ACTIVE", f"expected read set to remain ACTIVE, got {read_set_status!r}"

    # positive control: removing the read set first lets DeleteSequenceStore succeed
    omics.batch_delete_read_set(ids=[read_set_id], sequenceStoreId=store_id)
    _wait_read_set_gone(ctx, store_id, read_set_id)
    omics.delete_sequence_store(id=store_id)

    # the delete proves gone and unusable: an independent read moves the store towards
    # deletion (or removes it outright), and a second delete on the dead id also fails
    final_status = _wait_sequence_store_gone(ctx, store_id)
    dead_code, dead_message = _client_error(lambda: omics.delete_sequence_store(id=store_id))
    assert dead_code == "ResourceNotFoundException", (
        f"expected re-delete of a {final_status!r} sequence store to be ResourceNotFoundException, got {dead_code!r}"
    )
    assert dead_message == "The specified sequence store does not exist.", (
        f"expected message 'The specified sequence store does not exist.', got {dead_message!r}"
    )


def _fastq_bytes() -> bytes:
    seq = "ACGTACGTACGTACGTACGTACGTACGTACGTACGT"
    qual = "F" * len(seq)
    records = [
        f"@SIM2REAL:1:FLOWCELL:1:1:{n}:{n}\n{seq}\n+\n{qual}\n" for n in range(1, 5)
    ]
    return gzip.compress("".join(records).encode("ascii"))


def _client_error(fn) -> tuple[str, str]:
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_sequence_store(ctx) -> str:
    omics = ctx.client("omics")
    name = ctx.unique_name("sim2real-omics-seqstore-")
    store = omics.create_sequence_store(name=name, tags={"sim2real": CHECK})
    store_id = store["id"]
    ctx.on_cleanup(lambda: _best_effort_delete_store(ctx, store_id))
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


def _wait_read_set_gone(ctx, store_id: str, read_set_id: str) -> None:
    omics = ctx.client("omics")
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        # ListReadSets omits the (modelled-required) "readSets" key entirely when the
        # list is empty rather than returning [].
        ids_now = {item["id"] for item in omics.list_read_sets(sequenceStoreId=store_id).get("readSets", [])}
        if read_set_id not in ids_now:
            return
        time.sleep(2)
    raise AssertionError(f"read set {read_set_id} was not removed after BatchDeleteReadSet")


def _wait_sequence_store_gone(ctx, store_id: str) -> str:
    omics = ctx.client("omics")
    status = "DELETING"
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            status = omics.get_sequence_store(id=store_id)["status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return "GONE"
            raise
        if status != "DELETING":
            raise AssertionError(f"sequence store {store_id} moved to unexpected status {status!r} after delete")
        time.sleep(3)
    raise AssertionError(f"sequence store {store_id} did not disappear after DeleteSequenceStore (last status {status!r})")


def _best_effort_delete_store(ctx, store_id: str) -> None:
    try:
        ctx.client("omics").delete_sequence_store(id=store_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
