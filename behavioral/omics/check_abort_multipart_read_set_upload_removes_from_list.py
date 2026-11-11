"""abort-multipart-read-set-upload-removes-from-list."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "abort-multipart-read-set-upload-removes-from-list"
GROUP = "data-plane"
SERVICES = ["omics"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AbortMultipartReadSetUpload removes the in-progress upload from ListMultipartReadSetUploads and the aborted id becomes unusable."""
    omics = ctx.client("omics")
    store_id = _create_sequence_store(ctx)
    payload = b"@sim2real-read1\nACGTACGTAC\n+\nFFFFFFFFFF\n"

    upload = omics.create_multipart_read_set_upload(
        sequenceStoreId=store_id,
        sourceFileType="FASTQ",
        subjectId="sim2real-subject",
        sampleId="sim2real-sample",
        name=ctx.unique_name("sim2real-readset-"),
    )
    upload_id = upload["uploadId"]

    before_ids = {item["uploadId"] for item in omics.list_multipart_read_set_uploads(sequenceStoreId=store_id)["uploads"]}
    assert upload_id in before_ids, "created upload did not appear in ListMultipartReadSetUploads"

    part = omics.upload_read_set_part(
        sequenceStoreId=store_id,
        uploadId=upload_id,
        partSource="SOURCE1",
        partNumber=1,
        payload=payload,
    )
    assert part["checksum"], "positive control: uploading a part before abort must succeed"

    omics.abort_multipart_read_set_upload(sequenceStoreId=store_id, uploadId=upload_id)

    removed = False
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        after_ids = {item["uploadId"] for item in omics.list_multipart_read_set_uploads(sequenceStoreId=store_id)["uploads"]}
        if upload_id not in after_ids:
            removed = True
            break
        time.sleep(2)

    assert removed, f"aborted upload {upload_id} still appears in ListMultipartReadSetUploads"

    try:
        omics.upload_read_set_part(
            sequenceStoreId=store_id,
            uploadId=upload_id,
            partSource="SOURCE2",
            partNumber=1,
            payload=payload,
        )
        raise AssertionError(f"UploadReadSetPart on aborted upload {upload_id} unexpectedly succeeded")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message", "")
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException uploading a part to aborted upload {upload_id}, got {code!r}"
        )
        expected = (
            "The specified upload does not exist. The upload ID may be invalid, "
            "or the upload may have been aborted or completed."
        )
        assert message == expected, f"expected message {expected!r}, got {message!r}"


def _create_sequence_store(ctx) -> str:
    omics = ctx.client("omics")
    name = ctx.unique_name("sim2real-omics-seqstore-")
    store = omics.create_sequence_store(name=name)
    store_id = store["id"]
    ctx.on_cleanup(lambda: omics.delete_sequence_store(id=store_id))
    return store_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
