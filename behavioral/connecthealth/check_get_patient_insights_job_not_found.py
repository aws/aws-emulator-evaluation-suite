"""get-patient-insights-job-not-found."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

import botocore.auth
from behavioral_harness import tags
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

CHECK = "get-patient-insights-job-not-found"
GROUP = "error-semantics"
SERVICES = ["connecthealth"]


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected success raises, so an emulator that
    accepts what AWS refuses reads as a loud failure rather than a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
            time.sleep(2)


def _job_kwargs(domain_id: str, client_token: str, patient_id: str, fhir_endpoint: str, bucket: str) -> dict:
    return {
        "domainId": domain_id,
        "clientToken": client_token,
        "patientContext": {"patientId": patient_id, "dateOfBirth": "1990-01-01", "pronouns": "HE_HIM"},
        "insightsContext": {"insightsType": "PRE_VISIT"},
        "encounterContext": {"encounterReason": "Annual checkup"},
        "userContext": {"role": "CLINICIAN", "userId": "sim2real-user-1", "specialty": "PRIMARY_CARE"},
        "inputDataConfig": {
            # StartPatientInsightsJob empirically requires fhirServer, and the endpoint must name a
            # REAL HealthLake FHIR datastore ("Only HealthLake FHIR datastore is currently
            # supported", and "HealthLake datastore not found" for one that does not exist).
            "fhirServer": {"fhirEndpoint": fhir_endpoint},
            "s3Sources": [{"uri": f"s3://{bucket}/input.json"}],
        },
        "outputDataConfig": {"s3OutputPath": f"s3://{bucket}/output/"},
    }


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """GetPatientInsightsJob with a nonexistent jobId returns ResourceNotFoundException with its
    exact message, while a real job started in the same domain stays readable."""
    ch = ctx.client("connecthealth")
    s3 = ctx.client("s3")
    hl = ctx.client("healthlake")

    domain_id = _create_domain(ch, ctx.unique_name("sim2real-conh-dom-"), tags={"sim2real-probe": "true"})[
        "domainId"
    ]
    ctx.on_cleanup(lambda: ch.delete_domain(domainId=domain_id))

    bucket = ctx.unique_name("sim2real-conh-bkt-")
    _create_bucket(ctx, s3, bucket)
    fhir_endpoint = _create_fhir_datastore(ctx, hl, ctx.unique_name("sim2real-conh-hl-"))
    patient_id = ctx.unique_name("sim2real-patient-")
    _seed_patient(ctx, hl, fhir_endpoint, patient_id)

    token = ctx.unique_name("sim2real-conh-tok-")
    job_id = ch.start_patient_insights_job(
        **_job_kwargs(domain_id, token, patient_id, fhir_endpoint, bucket)
    )["jobId"]

    # positive control: the real job is readable and never FAILED against a seeded FHIR datastore;
    # the job runs asynchronously, so how far it has got by this read is the scheduler's, not graded.
    got = ch.get_patient_insights_job(domainId=domain_id, jobId=job_id)
    assert got["jobId"] == job_id, f"expected jobId {job_id!r}, got {got['jobId']!r}"
    assert got["jobStatus"] in ("SUBMITTED", "IN_PROGRESS", "SUCCEEDED"), (
        f"expected the started job to be SUBMITTED, IN_PROGRESS or SUCCEEDED, got "
        f"{got['jobStatus']!r} (statusDetails {got.get('statusDetails')!r})"
    )

    fake_job_id = "sim2real-fake-job-000000"  # within the 1-36 char length constraint, never created
    code, message = _client_error(lambda: ch.get_patient_insights_job(domainId=domain_id, jobId=fake_job_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    job_arn = f"arn:aws:health-agent:{ctx.region}:{ctx.account}:domain/{domain_id}/patient-insights-job/{fake_job_id}"
    expected = f"Job {job_arn} does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect isolation: the real job is still readable, unaffected
    still = ch.get_patient_insights_job(domainId=domain_id, jobId=job_id)["jobId"]
    assert still == job_id, f"expected the real job to remain readable after the not-found probe, got {still!r}"


# ===== helpers =====


def _create_bucket(ctx, s3, bucket: str) -> None:
    kwargs = {}
    if ctx.region != "us-east-1":  # S3 rejects an explicit LocationConstraint for us-east-1 itself
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})
    s3.put_object(Bucket=bucket, Key="input.json", Body=b'{"resourceType":"Bundle","type":"collection","entry":[]}')

    def _delete():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_delete)


def _create_fhir_datastore(ctx, hl, name: str) -> str:
    # StartPatientInsightsJob validates that its FHIR endpoint names a real, existing HealthLake FHIR
    # datastore in this account ("HealthLake datastore not found" on a fabricated one) — only HealthLake
    # is currently accepted as a FHIR server, so the datastore must actually exist, not just be
    # correctly shaped. Waiting out CREATING is also what keeps DeleteFHIRDatastore in teardown from
    # refusing and stranding the datastore.
    resp = hl.create_fhir_datastore(
        DatastoreName=name,
        DatastoreTypeVersion="R4",
        ClientToken=name,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
    # StartPatientInsightsJob resolves patientContext.patientId against a real FHIR Patient resource
    # in the datastore ("Patient could not be found in datastore" on an unseeded id) — this PUTs one
    # via the FHIR REST data plane.
    body = json.dumps(
        {
            "resourceType": "Patient",
            "id": patient_id,
            "identifier": [{"value": patient_id}],
            "name": [{"family": "Simparity", "given": ["Sim2real"]}],
            "gender": "unknown",
            "birthDate": "1990-01-01",
        }
    ).encode()
    status, resp = _signed_request(ctx, hl, "PUT", f"{fhir_endpoint.rstrip('/')}/Patient/{patient_id}", body_bytes=body)
    assert status in (200, 201), f"failed to seed Patient/{patient_id}: {status} {resp}"

    # confirm the write is actually readable back before StartPatientInsightsJob is asked to resolve it.
    # HealthLake's direct resource read is immediately consistent, but StartPatientInsightsJob may
    # resolve patientContext via HealthLake's (asynchronously indexed) search path rather than a
    # direct by-id read, so also poll a search-by-identifier until it is indexed.
    deadline = time.monotonic() + 60.0
    while True:
        rstatus, rresp = _signed_request(ctx, hl, "GET", f"{fhir_endpoint.rstrip('/')}/Patient/{patient_id}")
        if rstatus == 200:
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"seeded Patient/{patient_id} never became readable: {rstatus} {rresp}")
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
