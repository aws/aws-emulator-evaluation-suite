"""list-multipart-read-set-uploads-reflects-created-upload."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-multipart-read-set-uploads-reflects-created-upload"
GROUP = "data-plane"
SERVICES = ["omics"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListMultipartReadSetUploads reports the exact metadata of an in-progress multipart upload,
    and AbortMultipartReadSetUpload removes it again."""
    omics = ctx.client("omics")
    store_id = _create_sequence_store(ctx)
    upload_name = ctx.unique_name("sim2real-readset-")

    upload = omics.create_multipart_read_set_upload(
        sequenceStoreId=store_id,
        sourceFileType="FASTQ",
        subjectId="sim2real-subject-42",
        sampleId="sim2real-sample-42",
        name=upload_name,
    )
    upload_id = upload["uploadId"]
    ctx.on_cleanup(lambda: _best_effort_abort(ctx, store_id, upload_id))

    items = omics.list_multipart_read_set_uploads(sequenceStoreId=store_id)["uploads"]
    matching = [item for item in items if item["uploadId"] == upload_id]
    assert len(matching) == 1, f"expected exactly one listed upload for {upload_id}, found {len(matching)}"
    item = matching[0]
    assert item["sourceFileType"] == "FASTQ", f"expected sourceFileType FASTQ, got {item['sourceFileType']!r}"
    assert item["subjectId"] == "sim2real-subject-42", f"expected subjectId sim2real-subject-42, got {item['subjectId']!r}"
    assert item["sampleId"] == "sim2real-sample-42", f"expected sampleId sim2real-sample-42, got {item['sampleId']!r}"
    assert item["name"] == upload_name, f"expected name {upload_name!r}, got {item['name']!r}"

    omics.abort_multipart_read_set_upload(sequenceStoreId=store_id, uploadId=upload_id)
    removed = False
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        after_ids = {i["uploadId"] for i in omics.list_multipart_read_set_uploads(sequenceStoreId=store_id)["uploads"]}
        if upload_id not in after_ids:
            removed = True
            break
        time.sleep(2)
    assert removed, f"aborted upload {upload_id} still appears in ListMultipartReadSetUploads"


def _create_sequence_store(ctx) -> str:
    omics = ctx.client("omics")
    name = ctx.unique_name("sim2real-omics-seqstore-")
    store = omics.create_sequence_store(name=name)
    store_id = store["id"]
    ctx.on_cleanup(lambda: omics.delete_sequence_store(id=store_id))
    return store_id


def _best_effort_abort(ctx, store_id: str, upload_id: str) -> None:
    try:
        ctx.client("omics").abort_multipart_read_set_upload(sequenceStoreId=store_id, uploadId=upload_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
