"""list-read-set-upload-parts-reflects-uploaded-parts."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-read-set-upload-parts-reflects-uploaded-parts"
GROUP = "data-plane"
SERVICES = ["omics"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListReadSetUploadParts reports the exact partNumber/checksum/partSize of an uploaded part."""
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
    ctx.on_cleanup(lambda: omics.abort_multipart_read_set_upload(sequenceStoreId=store_id, uploadId=upload_id))

    part_response = omics.upload_read_set_part(
        sequenceStoreId=store_id,
        uploadId=upload_id,
        partSource="SOURCE1",
        partNumber=1,
        payload=payload,
    )

    parts = omics.list_read_set_upload_parts(
        sequenceStoreId=store_id, uploadId=upload_id, partSource="SOURCE1"
    )["parts"]

    assert len(parts) == 1, f"expected exactly one uploaded part listed, found {len(parts)}: {parts!r}"
    matching = [p for p in parts if p["partNumber"] == 1]
    assert len(matching) == 1, f"expected exactly one part 1, found {len(matching)}"
    part = matching[0]
    assert part["partSource"] == "SOURCE1", f"expected partSource SOURCE1, got {part['partSource']!r}"
    assert part["partSize"] == len(payload), f"expected partSize {len(payload)}, got {part['partSize']!r}"
    assert part["checksum"] == part_response["checksum"], (
        f"expected checksum {part_response['checksum']!r} from UploadReadSetPart, "
        f"got {part['checksum']!r} from ListReadSetUploadParts"
    )


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
