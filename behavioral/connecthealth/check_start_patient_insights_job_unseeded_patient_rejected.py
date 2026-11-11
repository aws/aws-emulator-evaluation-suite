"""start-patient-insights-job-unseeded-patient-rejected."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

import botocore.auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-patient-insights-job-unseeded-patient-rejected"
GROUP = "overly-permissive"
SERVICES = ["connecthealth"]

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


def _create_bucket(ctx, s3, bucket: str) -> None:
    kwargs = {}
    if ctx.region != "us-east-1":  # S3 rejects an explicit LocationConstraint for us-east-1 itself
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    s3.put_object(Bucket=bucket, Key="input.json", Body=b'{"resourceType":"Bundle","type":"collection","entry":[]}')


def _create_fhir_datastore(ctx, hl, name: str) -> str:
    resp = hl.create_fhir_datastore(
        DatastoreName=name,
        DatastoreTypeVersion="R4",
        ClientToken=name,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    datastore_id = resp["DatastoreId"]
    ctx.on_cleanup(lambda: hl.delete_fhir_datastore(DatastoreId=datastore_id))

    deadline = time.monotonic() + 240.0
    status = resp["DatastoreStatus"]
    while status == "CREATING":
        if time.monotonic() > deadline:
            raise TimeoutError(f"HealthLake datastore {datastore_id} did not leave CREATING within 240s")
        time.sleep(2)
        status = hl.describe_fhir_datastore(DatastoreId=datastore_id)["DatastoreProperties"]["DatastoreStatus"]
    assert status == "ACTIVE", f"HealthLake datastore {datastore_id} reached unexpected status {status!r}"

    return resp["DatastoreEndpoint"]


def _signed_request(ctx, healthlake_client, method, url, body_bytes=b""):
    creds = healthlake_client._request_signer._credentials
    headers = {"Content-Type": "application/fhir+json", "Accept": "application/fhir+json"}
    request = AWSRequest(method=method, url=url, data=body_bytes or None, headers=headers)
    botocore.auth.SigV4Auth(creds, "healthlake", ctx.region).add_auth(request)
    target_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(
        target_url, data=body_bytes if body_bytes else None, headers={**dict(request.headers), **route_headers}, method=method
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


def _seed_patient(ctx, hl, fhir_endpoint: str, patient_id: str) -> None:
    body = json.dumps(
        {
            "resourceType": "Patient",
            "id": patient_id,
            "identifier": [{"value": patient_id}],
            "name": [{"family": "Simparity", "given": ["Sim2real"]}],
            "gender": "unknown",
            "birthDate": _DATE_OF_BIRTH,
        }
    ).encode()
    # the datastore's FHIR data-plane endpoint can briefly 403 "Could not find specified datastore"
    # right after DescribeFHIRDatastore first reports ACTIVE, with no field to poll for readiness.
    deadline = time.monotonic() + 60.0
    while True:
        status, resp = _signed_request(ctx, hl, "PUT", f"{fhir_endpoint.rstrip('/')}/Patient/{patient_id}", body_bytes=body)
        if status in (200, 201):
            break
        diagnostics = (resp.get("issue") or [{}])[0].get("diagnostics")
        propagating = status == 403 and diagnostics == "Could not find specified datastore."
        if not propagating or time.monotonic() > deadline:
            raise AssertionError(f"failed to seed Patient/{patient_id}: {status} {resp}")
        time.sleep(2)

    deadline = time.monotonic() + 90.0
    while True:
        sstatus, sresp = _signed_request(
            ctx, hl, "GET", f"{fhir_endpoint.rstrip('/')}/Patient?identifier={patient_id}"
        )
        if sstatus == 200 and len(sresp.get("entry", [])) >= 1:
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"seeded Patient/{patient_id} never became searchable: {sstatus} {sresp}")
        time.sleep(2)


def _job_kwargs(domain_id: str, client_token: str, patient_id: str, dob: str, fhir_endpoint: str, bucket: str) -> dict:
    return {
        "domainId": domain_id,
        "clientToken": client_token,
        "patientContext": {"patientId": patient_id, "dateOfBirth": dob, "pronouns": "THEY_THEM"},
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
    """StartPatientInsightsJob on a well-formed patientId never seeded into the linked FHIR
    datastore is rejected with ValidationException "Patient could not be found in datastore.",
    while a real, seeded patient in the same domain and datastore is accepted."""
    ch = ctx.client("connecthealth")
    s3 = ctx.client("s3")
    hl = ctx.client("healthlake")

    bucket = ctx.unique_name("sim2real-conh-bkt-")
    _create_bucket(ctx, s3, bucket)

    def _delete_bucket():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_delete_bucket)

    fhir_endpoint = _create_fhir_datastore(ctx, hl, ctx.unique_name("sim2real-conh-hl-"))
    seeded_patient_id = ctx.unique_name("sim2real-patient-")
    _seed_patient(ctx, hl, fhir_endpoint, seeded_patient_id)

    domain_id = _create_domain(ch, ctx.unique_name("sim2real-conh-dom-"))["domainId"]
    ctx.on_cleanup(lambda: ch.delete_domain(domainId=domain_id))

    # negative: a well-formed patientId that was never written to the datastore is rejected.
    unseeded_patient_id = ctx.unique_name("sim2real-patient-")
    bad_token = ctx.unique_name("sim2real-conh-tok-")
    try:
        neg_result = ch.start_patient_insights_job(
            **_job_kwargs(domain_id, bad_token, unseeded_patient_id, _DATE_OF_BIRTH, fhir_endpoint, bucket)
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        msg = err.response["Error"].get("Message", "")
        assert code == "ValidationException", f"expected ValidationException, got {code!r} ({msg!r})"
        assert msg == "Patient could not be found in datastore.", (
            f"expected message 'Patient could not be found in datastore.', got {msg!r}"
        )
    else:
        raise AssertionError(f"expected the unseeded patientId to be rejected, but it SUCCEEDED: {neg_result!r}")

    # positive control: a real, seeded patient in the same domain and datastore is accepted, and the
    # FHIR search index can lag the seeded write by a short window.
    ok_token = ctx.unique_name("sim2real-conh-tok-")
    ok = None
    deadline = time.monotonic() + 90.0
    while ok is None:
        try:
            ok = ch.start_patient_insights_job(
                **_job_kwargs(domain_id, ok_token, seeded_patient_id, _DATE_OF_BIRTH, fhir_endpoint, bucket)
            )
        except ClientError as err:
            msg = err.response["Error"].get("Message", "")
            if err.response["Error"]["Code"] != "ValidationException" or "Patient could not be found" not in msg:
                raise
            if time.monotonic() > deadline:
                raise AssertionError(f"positive control never saw the FHIR Patient become visible: {err}") from err
            time.sleep(2.0)
    ok_job_id = ok["jobId"]
    assert ok_job_id, f"expected a jobId from the positive control, got {ok!r}"

    # effect isolation: the real job from the positive control is unaffected by the rejected attempt
    # against the unseeded patient, via an independent read (GetPatientInsightsJob, not the
    # StartPatientInsightsJob call that created it)
    real = ch.get_patient_insights_job(domainId=domain_id, jobId=ok_job_id)
    assert real["jobId"] == ok_job_id, f"expected the real job {ok_job_id!r} to still be readable, got {real!r}"
    assert real["jobStatus"] in ("SUBMITTED", "IN_PROGRESS", "SUCCEEDED"), (
        f"expected the accepted control job to be queued, running or done, got {real['jobStatus']!r} "
        f"(statusDetails {real.get('statusDetails')!r})"
    )

    # a fresh attempt against the SAME unseeded patientId still fails the same way: the earlier
    # rejection did not partially register the patient.
    retry_token = ctx.unique_name("sim2real-conh-tok-")
    try:
        retry_result = ch.start_patient_insights_job(
            **_job_kwargs(domain_id, retry_token, unseeded_patient_id, _DATE_OF_BIRTH, fhir_endpoint, bucket)
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        msg = err.response["Error"].get("Message", "")
        assert code == "ValidationException", f"expected ValidationException, got {code!r} ({msg!r})"
        assert msg == "Patient could not be found in datastore.", (
            f"expected message 'Patient could not be found in datastore.', got {msg!r}"
        )
    else:
        raise AssertionError(
            f"expected a retry against the still-unseeded patientId to be rejected, but it SUCCEEDED: {retry_result!r}"
        )

    # the control job settles before teardown, so it writes no output into a bucket being emptied.
    deadline = time.monotonic() + 180.0
    while real["jobStatus"] not in ("SUCCEEDED", "FAILED"):
        if time.monotonic() > deadline:
            raise AssertionError(f"control job {ok_job_id} did not reach a terminal state within 180s: {real!r}")
        time.sleep(3.0)
        real = ch.get_patient_insights_job(domainId=domain_id, jobId=ok_job_id)
    assert real["jobStatus"] == "SUCCEEDED", (
        f"expected the control job to SUCCEED, got {real['jobStatus']!r} (statusDetails {real.get('statusDetails')!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
