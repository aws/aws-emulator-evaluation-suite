"""start-patient-insights-job-conflicting-client-token-rejected."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

import botocore.auth
from behavioral_harness import tags
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

CHECK = "start-patient-insights-job-conflicting-client-token-rejected"
GROUP = "overly-permissive"
SERVICES = ["connecthealth"]


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


# budget.cleanup_timeout for behavioral/connecthealth, one deadline shared by every teardown of a run.
_TEARDOWN_S = 900.0 - 120.0
_JOB_TERMINAL = ("SUCCEEDED", "FAILED")


def _wait_until(teardown, probe, what: str) -> None:
    """Poll probe() every 2 s until it returns True, to the run's shared teardown deadline; then raise."""
    deadline = teardown.setdefault("t", time.monotonic() + _TEARDOWN_S)
    while not probe():
        if time.monotonic() >= deadline:
            raise TimeoutError(f"{what} within the teardown budget")
        time.sleep(2)


def _not_found(fn) -> bool:
    """True when fn() answers ResourceNotFoundException; any other error raises."""
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return True
        raise
    return False


def _delete_domain(teardown, ch, domain_id: str) -> None:
    """Delete the domain (and with it its jobs) and wait until GetDomain reports it gone."""
    if _not_found(lambda: ch.delete_domain(domainId=domain_id)):
        return

    def _gone():
        try:
            return ch.get_domain(domainId=domain_id)["status"] == "DELETED"
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return True
            raise

    _wait_until(teardown, _gone, f"domain {domain_id} was not deleted")


def _wait_jobs_terminal(teardown, ch, domain_id: str, job_ids: list) -> None:
    """Jobs cannot be stopped or deleted: wait until each is terminal before its inputs go."""
    for job_id in job_ids:
        _wait_until(
            teardown,
            lambda: ch.get_patient_insights_job(domainId=domain_id, jobId=job_id)["jobStatus"] in _JOB_TERMINAL,
            f"patient insights job {job_id} did not finish",
        )


def _kwargs(
    domain_id: str, client_token: str, patient_id: str, fhir_endpoint: str, bucket: str, encounter_reason: str
) -> dict:
    return {
        "domainId": domain_id,
        "clientToken": client_token,
        "patientContext": {"patientId": patient_id, "dateOfBirth": "1990-01-01", "pronouns": "HE_HIM"},
        "insightsContext": {"insightsType": "PRE_VISIT"},
        "encounterContext": {"encounterReason": encounter_reason},
        "userContext": {"role": "CLINICIAN", "userId": "sim2real-user-1", "specialty": "PRIMARY_CARE"},
        "inputDataConfig": {
            "fhirServer": {"fhirEndpoint": fhir_endpoint},
            "s3Sources": [{"uri": f"s3://{bucket}/input.json"}],
        },
        "outputDataConfig": {"s3OutputPath": f"s3://{bucket}/output/"},
    }


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A StartPatientInsightsJob replay with the same clientToken and identical parameters starts a new
    job with a different jobId, which GetPatientInsightsJob reads back with the submitted encounterReason;
    a malformed s3OutputPath is refused with ValidationException "Request validation failed"."""
    ch = ctx.client("connecthealth")
    teardown: dict = {}
    domain_id = _create_domain(ch, ctx.unique_name("sim2real-conh-dom-"), tags={"sim2real-probe": "true"})["domainId"]
    ctx.on_cleanup(lambda: _delete_domain(teardown, ch, domain_id))

    s3 = ctx.client("s3")
    hl = ctx.client("healthlake")
    bucket = ctx.unique_name("sim2real-conh-bkt-")
    _create_bucket(ctx, s3, bucket)
    fhir_endpoint = _create_fhir_datastore(ctx, teardown, hl, ctx.unique_name("sim2real-conh-hl-"))
    patient_id = ctx.unique_name("sim2real-patient-")
    _seed_patient(ctx, hl, fhir_endpoint, patient_id)

    token = ctx.unique_name("sim2real-conh-tok-")
    job_ids: list = []
    # Registered last so it runs first: the jobs finish before the datastore and bucket they use go.
    ctx.on_cleanup(lambda: _wait_jobs_terminal(teardown, ch, domain_id, job_ids))

    first = ch.start_patient_insights_job(
        **_kwargs(domain_id, token, patient_id, fhir_endpoint, bucket, "Annual checkup")
    )
    job_id = first["jobId"]
    job_ids.append(job_id)

    # The clientToken does not deduplicate: the identical replay is a second job.
    replay = ch.start_patient_insights_job(
        **_kwargs(domain_id, token, patient_id, fhir_endpoint, bucket, "Annual checkup")
    )
    job_ids.append(replay["jobId"])
    assert replay["jobId"] != job_id, f"expected the replay to start a new job, got the same jobId {job_id!r}"

    got = ch.get_patient_insights_job(domainId=domain_id, jobId=replay["jobId"])
    assert got["jobId"] == replay["jobId"], f"expected jobId {replay['jobId']!r}, got {got['jobId']!r}"
    assert got["encounterContext"]["encounterReason"] == "Annual checkup", (
        f"expected the submitted encounterReason, got {got['encounterContext']['encounterReason']!r}"
    )

    # Control: the call validates its input, so a target that starts a job for any request fails here.
    bad = _kwargs(
        domain_id, ctx.unique_name("sim2real-conh-tok-"), patient_id, fhir_endpoint, bucket, "Annual checkup"
    )
    bad["outputDataConfig"] = {"s3OutputPath": "not-an-s3-uri"}
    try:
        started = ch.start_patient_insights_job(**bad)
    except ClientError as err:
        refused = (err.response["Error"]["Code"], err.response["Error"].get("Message"))
    else:
        job_ids.append(started["jobId"])
        raise AssertionError(f"expected a malformed s3OutputPath to be refused, but a job started: {started!r}")
    assert refused == ("ValidationException", "Request validation failed"), (
        f"expected ValidationException 'Request validation failed' for a malformed s3OutputPath, got {refused!r}"
    )


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


def _create_fhir_datastore(ctx, teardown, hl, name: str) -> str:
    # StartPatientInsightsJob accepts only an existing HealthLake FHIR datastore as its FHIR server
    # ("HealthLake datastore not found" on a fabricated endpoint). Waiting out CREATING also keeps
    # DeleteFHIRDatastore in teardown from refusing.
    resp = hl.create_fhir_datastore(
        DatastoreName=name,
        DatastoreTypeVersion="R4",
        ClientToken=name,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    datastore_id = resp["DatastoreId"]
    ctx.on_cleanup(lambda: _delete_fhir_datastore(teardown, hl, datastore_id))

    deadline = time.monotonic() + 240.0
    status = resp["DatastoreStatus"]
    while status == "CREATING":
        if time.monotonic() > deadline:
            raise TimeoutError(f"HealthLake datastore {datastore_id} did not leave CREATING within 240s")
        time.sleep(2)
        status = hl.describe_fhir_datastore(DatastoreId=datastore_id)["DatastoreProperties"]["DatastoreStatus"]
    assert status == "ACTIVE", f"HealthLake datastore {datastore_id} reached unexpected status {status!r}"

    return resp["DatastoreEndpoint"]


def _delete_fhir_datastore(teardown, hl, datastore_id: str) -> None:
    """Delete the datastore and wait until DescribeFHIRDatastore reports it DELETED or gone."""
    if _not_found(lambda: hl.delete_fhir_datastore(DatastoreId=datastore_id)):
        return

    def _gone():
        try:
            props = hl.describe_fhir_datastore(DatastoreId=datastore_id)["DatastoreProperties"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return True
            raise
        return props["DatastoreStatus"] == "DELETED"

    _wait_until(teardown, _gone, f"HealthLake datastore {datastore_id} was not deleted")


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
