"""copy-image-set-creates-active-copy-with-matching-metadata."""
from __future__ import annotations

import gzip
import json
import struct
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "copy-image-set-creates-active-copy-with-matching-metadata"
GROUP = "data-plane"
SERVICES = ["medical-imaging"]


def _dcm_elem(group: int, elem: int, vr: str, value: bytes) -> bytes:
    if len(value) % 2:
        value += b"\x00" if vr == "UI" else b" "
    tag = struct.pack("<HH", group, elem)
    if vr in ("OB", "OW", "OF", "SQ", "UT", "UN"):
        return tag + vr.encode("ascii") + b"\x00\x00" + struct.pack("<I", len(value)) + value
    return tag + vr.encode("ascii") + struct.pack("<H", len(value)) + value


def _new_uid(prefix: str = "1.2.826.0.1.3680043.10.511") -> str:
    return f"{prefix}.{uuid.uuid4().int % (10 ** 16)}"


def _build_minimal_dicom(
    sop_class_uid: str,
    sop_instance_uid: str,
    study_uid: str,
    series_uid: str,
    patient_id: str,
    patient_name: str = "Sim^Test",
    rows: int = 4,
    cols: int = 4,
) -> bytes:
    pixel_data = bytes([128]) * (rows * cols)
    meta_body = b"".join(
        [
            _dcm_elem(0x0002, 0x0001, "OB", b"\x00\x01"),
            _dcm_elem(0x0002, 0x0002, "UI", sop_class_uid.encode()),
            _dcm_elem(0x0002, 0x0003, "UI", sop_instance_uid.encode()),
            _dcm_elem(0x0002, 0x0010, "UI", b"1.2.840.10008.1.2.1"),
            _dcm_elem(0x0002, 0x0012, "UI", b"1.2.826.0.1.3680043.9.7433.1.1"),
        ]
    )
    meta = _dcm_elem(0x0002, 0x0000, "UL", struct.pack("<I", len(meta_body))) + meta_body
    dataset = b"".join(
        [
            _dcm_elem(0x0008, 0x0016, "UI", sop_class_uid.encode()),
            _dcm_elem(0x0008, 0x0018, "UI", sop_instance_uid.encode()),
            _dcm_elem(0x0008, 0x0020, "DA", b"20240101"),
            _dcm_elem(0x0008, 0x0030, "TM", b"000000"),
            _dcm_elem(0x0008, 0x0060, "CS", b"OT"),
            _dcm_elem(0x0010, 0x0010, "PN", patient_name.encode()),
            _dcm_elem(0x0010, 0x0020, "LO", patient_id.encode()),
            _dcm_elem(0x0010, 0x0040, "CS", b"O"),
            _dcm_elem(0x0020, 0x000D, "UI", study_uid.encode()),
            _dcm_elem(0x0020, 0x000E, "UI", series_uid.encode()),
            _dcm_elem(0x0020, 0x0010, "SH", b"1"),
            _dcm_elem(0x0020, 0x0011, "IS", b"1"),
            _dcm_elem(0x0020, 0x0013, "IS", b"1"),
            _dcm_elem(0x0028, 0x0002, "US", struct.pack("<H", 1)),
            _dcm_elem(0x0028, 0x0004, "CS", b"MONOCHROME2"),
            _dcm_elem(0x0028, 0x0010, "US", struct.pack("<H", rows)),
            _dcm_elem(0x0028, 0x0011, "US", struct.pack("<H", cols)),
            _dcm_elem(0x0028, 0x0100, "US", struct.pack("<H", 8)),
            _dcm_elem(0x0028, 0x0101, "US", struct.pack("<H", 8)),
            _dcm_elem(0x0028, 0x0102, "US", struct.pack("<H", 7)),
            _dcm_elem(0x0028, 0x0103, "US", struct.pack("<H", 0)),
            _dcm_elem(0x7FE0, 0x0010, "OW", pixel_data),
        ]
    )
    return b"\x00" * 128 + b"DICM" + meta + dataset


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_import_role_and_bucket(ctx) -> dict:
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    bucket = ctx.unique_name("sim2real-mi-").lower().replace("_", "-")
    # us-east-1 is the one region where S3's CreateBucket rejects an explicit
    # LocationConstraint; this is the real API contract, not a region assumption.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))

    role_name = ctx.unique_name("sim2real-mi-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "medical-imaging.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": [f"arn:aws:s3:::{bucket}"]},
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": [f"arn:aws:s3:::{bucket}/in/*"]},
            {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": [f"arn:aws:s3:::{bucket}/out/*"]},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="s3access", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3access"))

    role_arn = f"arn:aws:iam::{ctx.client('sts').get_caller_identity()['Account']}:role/{role_name}"
    return {"bucket": bucket, "role_arn": role_arn}


def _start_import_job_retry(mi, timeout_s: float = 120.0, **kwargs) -> dict:
    """IAM role/policy changes can take up to ~60s to propagate across IAM, so the service may
    not yet be able to assume the just-created role; retry only on AccessDeniedException/
    ValidationException (propagation delay) with a bounded deadline -- any other error must
    propagate immediately, unmasked."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return mi.start_dicom_import_job(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException") and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _wait_active(mi, datastore_id: str, timeout_s: float = 300.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = mi.get_datastore(datastoreId=datastore_id)["datastoreProperties"]["datastoreStatus"]
        if status == "ACTIVE":
            return
        time.sleep(3)
    raise AssertionError("datastore never reached ACTIVE")


def _wait_job_terminal(mi, datastore_id: str, job_id: str, timeout_s: float = 300.0) -> dict:
    deadline = time.monotonic() + timeout_s
    props = None
    while time.monotonic() < deadline:
        props = mi.get_dicom_import_job(datastoreId=datastore_id, jobId=job_id)["jobProperties"]
        if props["jobStatus"] in ("COMPLETED", "FAILED"):
            return props
        time.sleep(5)
    raise AssertionError(f"import job never reached a terminal state, last={props}")


def _find_image_set_id(mi, datastore_id: str, study_uid: str, timeout_s: float = 60.0) -> str:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = mi.search_image_sets(
            datastoreId=datastore_id,
            searchCriteria={
                "filters": [{"operator": "EQUAL", "values": [{"DICOMStudyInstanceUID": study_uid}]}]
            },
        )
        summaries = resp["imageSetsMetadataSummaries"]
        if summaries:
            return summaries[0]["imageSetId"]
        time.sleep(3)
    raise AssertionError("import COMPLETED but no image set was ever indexed for the study")


def _read_metadata(mi, datastore_id: str, image_set_id: str) -> dict:
    resp = mi.get_image_set_metadata(datastoreId=datastore_id, imageSetId=image_set_id)
    return json.loads(gzip.decompress(resp["imageSetMetadataBlob"].read()))


def _cleanup_delete_image_set(mi, datastore_id: str, image_set_id: str) -> None:
    try:
        mi.delete_image_set(datastoreId=datastore_id, imageSetId=image_set_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _cleanup_delete_datastore(mi, datastore_id: str, timeout_s: float = 180.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            mi.delete_datastore(datastoreId=datastore_id)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code == "ConflictException":
                time.sleep(5)
                continue
            raise
    raise AssertionError("could not delete datastore during cleanup (still conflicting)")


def _wait_copy_terminal(mi, datastore_id: str, image_set_id: str, timeout_s: float = 300.0) -> dict:
    deadline = time.monotonic() + timeout_s
    props = None
    while time.monotonic() < deadline:
        props = mi.get_image_set(datastoreId=datastore_id, imageSetId=image_set_id)
        if props["imageSetWorkflowStatus"] in ("COPIED", "COPY_FAILED"):
            return props
        time.sleep(3)
    raise AssertionError(f"image set never left the copying workflow, last={props}")


# ===== check =====

@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CopyImageSet creates a brand-new, ACTIVE destination image set that carries the same
    normalized Patient/Study DICOM metadata as its source, and the source itself settles back
    into imageSetWorkflowStatus COPIED once the copy completes."""
    mi = ctx.client("medical-imaging")
    s3 = ctx.client("s3")

    datastore_id = mi.create_datastore(
        datastoreName=ctx.unique_name("sim2real-mi-ds-"),
        clientToken=ctx.unique_name("sim2real-mi-tok-"),
    )["datastoreId"]
    ctx.on_cleanup(lambda: _cleanup_delete_datastore(mi, datastore_id))
    _wait_active(mi, datastore_id)

    infra = _create_import_role_and_bucket(ctx)
    bucket, role_arn = infra["bucket"], infra["role_arn"]

    study_uid = _new_uid()
    series_uid = _new_uid()
    sop_instance_uid = _new_uid()
    patient_id = "sim2real-patient-copy-001"
    dicom_bytes = _build_minimal_dicom(
        sop_class_uid="1.2.840.10008.5.1.4.1.1.7",
        sop_instance_uid=sop_instance_uid,
        study_uid=study_uid,
        series_uid=series_uid,
        patient_id=patient_id,
    )
    s3.put_object(Bucket=bucket, Key="in/instance1.dcm", Body=dicom_bytes)

    job_id = _start_import_job_retry(
        mi,
        jobName=ctx.unique_name("sim2real-mi-job-"),
        datastoreId=datastore_id,
        dataAccessRoleArn=role_arn,
        clientToken=ctx.unique_name("sim2real-mi-tok-"),
        inputS3Uri=f"s3://{bucket}/in/",
        outputS3Uri=f"s3://{bucket}/out/",
    )["jobId"]
    job_props = _wait_job_terminal(mi, datastore_id, job_id)
    assert job_props["jobStatus"] == "COMPLETED", job_props

    source_id = _find_image_set_id(mi, datastore_id, study_uid)
    ctx.on_cleanup(lambda: _cleanup_delete_image_set(mi, datastore_id, source_id))
    source = mi.get_image_set(datastoreId=datastore_id, imageSetId=source_id)
    source_version = source["versionId"]

    copy_resp = mi.copy_image_set(
        datastoreId=datastore_id,
        sourceImageSetId=source_id,
        copyImageSetInformation={"sourceImageSet": {"latestVersionId": source_version}},
    )
    dest_id = copy_resp["destinationImageSetProperties"]["imageSetId"]
    ctx.on_cleanup(lambda: _cleanup_delete_image_set(mi, datastore_id, dest_id))
    assert dest_id != source_id, f"copy must mint a new image set id, got same id {dest_id!r} back"

    dest_final = _wait_copy_terminal(mi, datastore_id, dest_id)
    assert dest_final["imageSetWorkflowStatus"] == "COPIED", dest_final
    assert dest_final["imageSetState"] == "ACTIVE", (
        f"expected destination imageSetState ACTIVE, got {dest_final['imageSetState']!r}"
    )

    source_final = _wait_copy_terminal(mi, datastore_id, source_id)
    assert source_final["imageSetWorkflowStatus"] == "COPIED", source_final
    assert source_final["imageSetState"] == "ACTIVE", (
        f"expected source imageSetState ACTIVE after copy settles, got {source_final['imageSetState']!r}"
    )

    source_meta = _read_metadata(mi, datastore_id, source_id)
    dest_meta = _read_metadata(mi, datastore_id, dest_id)
    assert dest_meta["Patient"] == source_meta["Patient"], (
        f"copy must carry the same normalized Patient DICOM metadata: "
        f"source={source_meta['Patient']!r} dest={dest_meta['Patient']!r}"
    )
    assert dest_meta["Patient"]["DICOM"]["PatientID"] == patient_id, (
        f"expected PatientID {patient_id!r}, got {dest_meta['Patient']['DICOM']['PatientID']!r}"
    )
    assert dest_meta["Study"] == source_meta["Study"], (
        f"copy must carry the same normalized Study DICOM metadata: "
        f"source={source_meta['Study']!r} dest={dest_meta['Study']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
