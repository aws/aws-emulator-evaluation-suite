"""dicom-import-job-success-creates-active-image-set."""
from __future__ import annotations

import gzip
import json
import struct
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dicom-import-job-success-creates-active-image-set"
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
    """Build a byte-minimal but structurally valid DICOM P10 file (Explicit VR Little Endian,
    Secondary Capture Image Storage) suitable for HealthImaging import."""
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
    if ctx.region == "us-east-1":
        # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})

    role_name = ctx.unique_name("sim2real-mi-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "medical-imaging.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
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


def _start_import_job_retry(mi, timeout_s: float = 120.0, **kwargs):
    """Retries on AccessDeniedException/ValidationException while IAM eventual consistency
    makes the just-created role or its just-attached policy temporarily unrecognized."""
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


def _wait_active(mi, datastore_id: str, timeout_s: float = 120.0) -> None:
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


def _first_image_frame_id(metadata: dict) -> str:
    for series in metadata.get("Study", {}).get("Series", {}).values():
        for instance in series.get("Instances", {}).values():
            frames = instance.get("ImageFrames", [])
            if frames:
                return frames[0]["ID"]
    raise AssertionError(f"no image frame present in image set metadata: {metadata}")


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



# ===== check =====

@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A DICOM P10 file uploaded to S3 and imported via StartDICOMImportJob completes, is
    organized into an ACTIVE image set discoverable via SearchImageSets, and both its
    normalized metadata and raw pixel data are retrievable end to end."""
    mi = ctx.client("medical-imaging")
    s3 = ctx.client("s3")

    datastore_id = mi.create_datastore(
        datastoreName=ctx.unique_name("sim2real-mi-ds-"),
        clientToken=ctx.unique_name("sim2real-mi-tok-"),
        tags={"sim2real": "true"},
    )["datastoreId"]
    ctx.on_cleanup(lambda: _cleanup_delete_datastore(mi, datastore_id))
    _wait_active(mi, datastore_id)

    infra = _create_import_role_and_bucket(ctx)
    bucket, role_arn = infra["bucket"], infra["role_arn"]

    study_uid = _new_uid()
    series_uid = _new_uid()
    sop_instance_uid = _new_uid()
    patient_id = "sim2real-patient-001"
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

    image_set_id = _find_image_set_id(mi, datastore_id, study_uid)
    ctx.on_cleanup(lambda: _cleanup_delete_image_set(mi, datastore_id, image_set_id))

    image_set = mi.get_image_set(datastoreId=datastore_id, imageSetId=image_set_id)
    assert image_set["imageSetState"] == "ACTIVE", image_set["imageSetState"]
    assert image_set["imageSetWorkflowStatus"] == "IMPORTED", image_set["imageSetWorkflowStatus"]

    meta_resp = mi.get_image_set_metadata(datastoreId=datastore_id, imageSetId=image_set_id)
    raw = meta_resp["imageSetMetadataBlob"].read()
    metadata = json.loads(gzip.decompress(raw))
    assert metadata["Patient"]["DICOM"]["PatientID"] == patient_id, metadata["Patient"]["DICOM"]["PatientID"]

    frame_id = _first_image_frame_id(metadata)
    frame_resp = mi.get_image_frame(
        datastoreId=datastore_id,
        imageSetId=image_set_id,
        imageFrameInformation={"imageFrameId": frame_id},
    )
    frame_bytes = frame_resp["imageFrameBlob"].read()
    assert len(frame_bytes) > 0, len(frame_bytes)
    assert frame_resp.get("contentType", "").startswith("image/"), frame_resp.get("contentType")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
