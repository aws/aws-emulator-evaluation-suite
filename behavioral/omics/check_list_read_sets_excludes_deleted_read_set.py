"""list-read-sets-excludes-deleted-read-set."""
from __future__ import annotations

import gzip
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-read-sets-excludes-deleted-read-set"
GROUP = "data-plane"
SERVICES = ["omics"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A read set appears in ListReadSets once ACTIVE and disappears once BatchDeleteReadSet removes it."""
    omics = ctx.client("omics")
    store_id = _create_sequence_store(ctx)
    read_set_id = _create_active_read_set(ctx, store_id)

    ids_present = {item["id"] for item in omics.list_read_sets(sequenceStoreId=store_id)["readSets"]}
    assert read_set_id in ids_present, "ACTIVE read set did not appear in ListReadSets"

    delete_result = omics.batch_delete_read_set(ids=[read_set_id], sequenceStoreId=store_id)
    errored_ids = {e["id"] for e in delete_result.get("errors", [])}
    assert read_set_id not in errored_ids, (
        f"BatchDeleteReadSet reported an error for {read_set_id}: {delete_result.get('errors')}"
    )

    removed = False
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        ids_now = {item["id"] for item in omics.list_read_sets(sequenceStoreId=store_id).get("readSets", [])}
        if read_set_id not in ids_now:
            removed = True
            break
        time.sleep(2)

    assert removed, f"deleted read set {read_set_id} still appears in ListReadSets"

    try:
        after = omics.get_read_set_metadata(sequenceStoreId=store_id, id=read_set_id)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message", "")
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException for a deleted read set, got {code!r}"
        )
        assert message == "The specified readset does not exist.", (
            f"expected message 'The specified readset does not exist.', got {message!r}"
        )
    else:
        assert after["status"] in ("DELETED", "DELETING"), (
            f"deleted read set {read_set_id} still reports status {after['status']!r} via GetReadSetMetadata"
        )


def _fastq_bytes() -> bytes:
    seq = "ACGTACGTAC" * 10
    qual = "F" * len(seq)
    reads = [f"@sim2real-read{i}\n{seq}\n+\n{qual}\n" for i in range(1, 51)]
    return gzip.compress("".join(reads).encode())


def _create_sequence_store(ctx) -> str:
    omics = ctx.client("omics")
    name = ctx.unique_name("sim2real-omics-seqstore-")
    store = omics.create_sequence_store(name=name, tags={"sim2real-check": CHECK})
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
        tags={"sim2real-check": CHECK},
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
    deadline = time.monotonic() + 300
    meta = {}
    while status == "PROCESSING_UPLOAD" and time.monotonic() < deadline:
        time.sleep(5)
        meta = omics.get_read_set_metadata(sequenceStoreId=store_id, id=read_set_id)
        status = meta["status"]
    if status != "ACTIVE":
        raise AssertionError(
            f"prerequisite read set {read_set_id} ended in status {status!r} "
            f"({meta.get('statusMessage')!r})"
        )
    return read_set_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
