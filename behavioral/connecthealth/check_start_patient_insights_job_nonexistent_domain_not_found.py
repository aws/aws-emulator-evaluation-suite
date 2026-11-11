"""start-patient-insights-job-nonexistent-domain-not-found."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

import botocore.auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-patient-insights-job-nonexistent-domain-not-found"
GROUP = "error-semantics"
SERVICES = ["connecthealth"]

_PATIENT_ID = "sim2real-patient-1"
_DATE_OF_BIRTH = "1990-01-01"


def _create_domain(ch, name, **extra):
    deadline = time.monotonic() + 300.0
    while True:
        try:
            return ch.create_domain(name=name, **extra)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "")
            if code not in ("ServiceQuotaExceededException", "ValidationException") or "maximum limit" not in msg:
                raise
            if time.monotonic() > deadline:
                raise
            time.sleep(5.0)


def _create_input_bucket(s3, bucket: str, region: str) -> None:
    kwargs = {"Bucket": bucket}
    if region != "us-east-1":  # S3 CreateBucket rejects an explicit LocationConstraint of us-east-1 itself
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    s3.put_object(Bucket=bucket, Key="input.json", Body=b"{}")


def _create_active_fhir_datastore(ctx, healthlake) -> str:
    created = healthlake.create_fhir_datastore(
        DatastoreTypeVersion="R4",
        DatastoreName=ctx.unique_name("sim2real-conh-fhir-"),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    datastore_id = created["DatastoreId"]

    deadline = time.monotonic() + 280.0
    status = created["DatastoreStatus"]
    while True:
        if status in ("ACTIVE", "CREATE_FAILED"):
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"FHIR datastore {datastore_id} did not settle within 280s (last status {status!r})")
        time.sleep(2.0)
        status = healthlake.describe_fhir_datastore(DatastoreId=datastore_id)["DatastoreProperties"][
            "DatastoreStatus"
        ]
    if status != "ACTIVE":
        raise AssertionError(f"FHIR datastore {datastore_id} did not reach ACTIVE (last status {status!r})")
    return datastore_id


def _signed_fhir_request(ctx, healthlake, method: str, url: str, body_bytes: bytes = b""):
    creds = healthlake._request_signer._credentials
    headers = {"Content-Type": "application/fhir+json", "Accept": "application/fhir+json"}
    request = AWSRequest(method=method, url=url, data=body_bytes or None, headers=headers)
    botocore.auth.SigV4Auth(creds, "healthlake", ctx.region).add_auth(request)
    target_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(target_url, data=body_bytes or None, headers={**dict(request.headers), **route_headers}, method=method)
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


def _put_fhir_patient(ctx, healthlake, fhir_endpoint: str) -> None:
    # StartPatientInsightsJob resolves patientContext.patientId against a real Patient resource in
    # the linked HealthLake datastore ("Patient could not be found in datastore" otherwise).
    body = json.dumps(
        {
            "resourceType": "Patient",
            "id": _PATIENT_ID,
            "identifier": [{"system": "urn:sim2real:patient", "value": _PATIENT_ID}],
            "birthDate": _DATE_OF_BIRTH,
            "gender": "male",
        }
    ).encode()
    status, resp = _signed_fhir_request(
        ctx, healthlake, "PUT", f"{fhir_endpoint.rstrip('/')}/Patient/{_PATIENT_ID}", body_bytes=body
    )
    assert status in (200, 201), f"expected the FHIR Patient PUT to succeed, got {status}: {resp}"

    status, fetched = _signed_fhir_request(ctx, healthlake, "GET", f"{fhir_endpoint.rstrip('/')}/Patient/{_PATIENT_ID}")
    assert status == 200 and fetched.get("id") == _PATIENT_ID, (
        f"expected the FHIR Patient to be immediately readable back, got {status}: {fetched}"
    )


def _job_kwargs(domain_id: str, client_token: str, bucket: str, fhir_endpoint: str) -> dict:
    return {
        "domainId": domain_id,
        "clientToken": client_token,
        "patientContext": {"patientId": _PATIENT_ID, "dateOfBirth": _DATE_OF_BIRTH, "pronouns": "HE_HIM"},
        "insightsContext": {"insightsType": "PRE_VISIT"},
        "encounterContext": {"encounterReason": "Annual checkup"},
        "userContext": {"role": "CLINICIAN", "userId": "sim2real-user-1", "specialty": "PRIMARY_CARE"},
        "inputDataConfig": {
            "fhirServer": {"fhirEndpoint": fhir_endpoint},
            "s3Sources": [{"uri": f"s3://{bucket}/input.json"}],
        },
        "outputDataConfig": {"s3OutputPath": f"s3://{bucket}/output/"},
    }


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """StartPatientInsightsJob on a well-formed nonexistent domainId returns AccessDeniedException
    ("Domain is not valid."), while a real domain with a FHIR datastore and Patient accepts the job."""
    ch = ctx.client("connecthealth")
    s3 = ctx.client("s3")
    healthlake = ctx.client("healthlake")

    bucket = ctx.unique_name("sim2real-conh-bkt-")
    _create_input_bucket(s3, bucket, ctx.region)

    def _delete_bucket():
        # the accepted job writes its output under the bucket, so empty every key, not just the input
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_delete_bucket)

    fhir_datastore_id = _create_active_fhir_datastore(ctx, healthlake)
    ctx.on_cleanup(lambda: healthlake.delete_fhir_datastore(DatastoreId=fhir_datastore_id))
    fhir_endpoint = healthlake.describe_fhir_datastore(DatastoreId=fhir_datastore_id)["DatastoreProperties"][
        "DatastoreEndpoint"
    ]
    _put_fhir_patient(ctx, healthlake, fhir_endpoint)

    domain_id = _create_domain(ch, ctx.unique_name("sim2real-conh-dom-"))["domainId"]
    ctx.on_cleanup(lambda: ch.delete_domain(domainId=domain_id))

    # positive control: a real Domain accepts the job. HealthLake's FHIR search index can lag a
    # freshly-written Patient by a short window, so retry on that specific message.
    ok_token = ctx.unique_name("sim2real-conh-tok-")
    ok = None
    deadline = time.monotonic() + 90.0
    while ok is None:
        try:
            ok = ch.start_patient_insights_job(**_job_kwargs(domain_id, ok_token, bucket, fhir_endpoint))
        except ClientError as err:
            msg = err.response["Error"].get("Message", "")
            if err.response["Error"]["Code"] != "ValidationException" or "Patient could not be found" not in msg:
                raise
            if time.monotonic() > deadline:
                raise AssertionError(f"positive control never saw the FHIR Patient become visible: {err}") from err
            time.sleep(2.0)
    ok_job_id = ok["jobId"]
    assert ok_job_id, f"expected a jobId from the positive control, got {ok!r}"

    # negative: a well-formed but nonexistent domainId is rejected, not with
    # ResourceNotFoundException -- StartPatientInsightsJob
    # answers AccessDeniedException/"Domain is not valid." instead, the same anti-enumeration
    # pattern IAM resource-ARN authorization uses elsewhere: it will not confirm or deny a
    # resource's existence to a caller before checking access on it.
    fake_domain_id = "dom-" + "3" * 20  # matches ^(hai-|dom-)[a-z0-9]+$, never created
    bad_token = ctx.unique_name("sim2real-conh-tok-")
    try:
        neg_result = ch.start_patient_insights_job(**_job_kwargs(fake_domain_id, bad_token, bucket, fhir_endpoint))
    except ClientError as err:
        code = err.response["Error"]["Code"]
        msg = err.response["Error"].get("Message", "")
        assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r} ({msg!r})"
        assert msg == "Domain is not valid.", f"expected message 'Domain is not valid.', got {msg!r}"
    else:
        raise AssertionError(f"expected the nonexistent domainId to be rejected, but it SUCCEEDED: {neg_result!r}")

    # effect isolation: the real job from the positive control is unaffected by the failed attempt
    # against the nonexistent domain, via an independent read (GetPatientInsightsJob, not the
    # StartPatientInsightsJob call that created it)
    real = ch.get_patient_insights_job(domainId=domain_id, jobId=ok_job_id)
    assert real["jobId"] == ok_job_id, f"expected the real job {ok_job_id!r} to still be readable, got {real!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
