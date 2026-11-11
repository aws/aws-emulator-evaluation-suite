"""fhir-import-job-delivers-resource-to-datastore."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

import botocore.auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fhir-import-job-delivers-resource-to-datastore"
GROUP = "data-plane"
SERVICES = ["healthlake"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A bulk FHIR import job reaches COMPLETED and the imported resource becomes queryable over the FHIR REST API."""
    healthlake = ctx.client("healthlake")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    kms = ctx.client("kms")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]

    # --- FHIR datastore ---
    ds_name = ctx.unique_name("sim2real-hl-import-")
    created_ds = healthlake.create_fhir_datastore(
        DatastoreName=ds_name,
        DatastoreTypeVersion="R4",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    datastore_id = created_ds["DatastoreId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: healthlake.delete_fhir_datastore(DatastoreId=datastore_id)))

    props = _poll_until(
        lambda: healthlake.describe_fhir_datastore(DatastoreId=datastore_id)["DatastoreProperties"],
        lambda p: p["DatastoreStatus"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=2100.0,
        interval_s=20.0,
    )
    assert props["DatastoreStatus"] == "ACTIVE", f"datastore reached {props['DatastoreStatus']}"
    datastore_arn = props["DatastoreArn"]

    # --- S3 bucket ---
    bucket = ctx.unique_name("sim2real-hl-import").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})
    ctx.on_cleanup(lambda: _best_effort(lambda: _empty_and_delete_bucket(s3, bucket)))

    # --- KMS key ---
    key_arn = kms.create_key(
        Description="sim2real HealthLake import test key",
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7)
        )
    )

    # --- IAM data access role ---
    role_name = ctx.unique_name("sim2real-hl-import-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "healthlake.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnEquals": {"aws:SourceArn": datastore_arn},
                },
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: iam.delete_role(RoleName=role_name)))

    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket", "s3:GetBucketPublicAccessBlock", "s3:GetEncryptionConfiguration"],
                "Resource": f"arn:aws:s3:::{bucket}",
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": f"arn:aws:s3:::{bucket}/*",
            },
            {
                "Effect": "Allow",
                "Action": ["kms:DescribeKey", "kms:GenerateDataKey*"],
                "Resource": key_arn,
            },
        ],
    }
    policy_name = "sim2real-hl-import-policy"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(permissions_policy)
    )
    ctx.on_cleanup(
        lambda: _best_effort(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    )

    # --- input NDJSON ---
    marker_id = ctx.unique_name("sim2real-import-")
    patient_resource = {
        "resourceType": "Patient",
        "id": marker_id,
        "identifier": [{"system": "urn:sim2real:import-test", "value": marker_id}],
        "name": [{"family": "SimparityImportSurname", "given": ["Bulk"]}],
        "gender": "unknown",
    }
    s3.put_object(
        Bucket=bucket, Key="input/patient.ndjson", Body=(json.dumps(patient_resource) + "\n").encode()
    )

    # --- start import job (retry briefly for IAM propagation) ---
    started = _retry_on_access_denied(
        lambda: healthlake.start_fhir_import_job(
            JobName=ctx.unique_name("sim2real-import-job-"),
            InputDataConfig={"S3Uri": f"s3://{bucket}/input/"},
            JobOutputDataConfig={
                "S3Configuration": {"S3Uri": f"s3://{bucket}/output/", "KmsKeyId": key_arn}
            },
            DataAccessRoleArn=role_arn,
            DatastoreId=datastore_id,
            ClientToken=ctx.unique_name("sim2real-token-"),
        ),
        timeout_s=90.0,
    )
    job_id = started["JobId"]

    job_props = _poll_until(
        lambda: healthlake.describe_fhir_import_job(DatastoreId=datastore_id, JobId=job_id)[
            "ImportJobProperties"
        ],
        lambda p: p["JobStatus"]
        in ("COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"),
        timeout_s=1200.0,
        interval_s=15.0,
    )
    assert job_props["JobStatus"] == "COMPLETED", (
        f"import job ended as {job_props['JobStatus']}: {job_props.get('Message')}"
    )

    # --- verify the imported resource is now queryable over the native FHIR REST API ---
    endpoint = props["DatastoreEndpoint"].rstrip("/")
    status, fetched = _signed_fhir_request(ctx, healthlake, "GET", f"{endpoint}/Patient/{marker_id}")
    assert status == 200, f"imported Patient not readable via FHIR REST: {status} {fetched}"
    assert fetched["resourceType"] == "Patient", f"expected resourceType Patient, got {fetched.get('resourceType')}"
    assert fetched["id"] == marker_id, f"expected id {marker_id}, got {fetched.get('id')}"
    assert fetched["name"][0]["family"] == "SimparityImportSurname", (
        f"expected family name SimparityImportSurname, got {fetched.get('name')}"
    )


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "NoSuchBucket",
            "NoSuchEntity",
            "NotFoundException",
            "ResourceNotFoundException",
        ):
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed={last!r}")


def _is_iam_propagation_error(exc):
    code = exc.response["Error"]["Code"]
    message = exc.response["Error"].get("Message", "")
    if code == "AccessDeniedException":
        return True
    # HealthLake validates the data access role's trust policy synchronously and, while the
    # just-created role/policy is still propagating, surfaces that as ValidationException rather
    # than AccessDeniedException.
    return code == "ValidationException" and "not authorized to assume role" in message


def _retry_on_access_denied(fn, *, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if not _is_iam_propagation_error(exc):
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"still not authorized to assume role after {timeout_s}s (IAM propagation?): {last_exc}")


def _empty_and_delete_bucket(s3_client, bucket):
    paginator = s3_client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objects = [{"Key": obj["Key"]} for obj in page.get("Contents", [])]
        if objects:
            failed = s3_client.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3_client.delete_bucket(Bucket=bucket)


def _signed_fhir_request(ctx, healthlake_client, method, url, body_bytes=b""):
    creds = healthlake_client._request_signer._credentials
    headers = {"Content-Type": "application/fhir+json", "Accept": "application/fhir+json"}
    request = AWSRequest(method=method, url=url, data=body_bytes or None, headers=headers)
    botocore.auth.SigV4Auth(creds, "healthlake", ctx.region).add_auth(request)
    prepared_headers = dict(request.headers)
    target_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(
        target_url, data=body_bytes if body_bytes else None, headers={**prepared_headers, **route_headers}, method=method
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, {"raw": raw.decode(errors="replace")}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
