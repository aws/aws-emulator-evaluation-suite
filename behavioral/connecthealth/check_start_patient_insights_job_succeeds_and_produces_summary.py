"""start-patient-insights-job-succeeds-and-produces-summary."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

import botocore.auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-patient-insights-job-succeeds-and-produces-summary"
GROUP = "data-plane"
SERVICES = ["connecthealth"]

_DATE_OF_BIRTH = "1988-03-03"


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
    # StartPatientInsightsJob validates that its FHIR endpoint names a real, existing HealthLake FHIR
    # datastore in this account; only HealthLake is currently accepted as a FHIR server.
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
    # StartPatientInsightsJob resolves patientContext.patientId against a real FHIR Patient resource
    # in the datastore ("Patient could not be found in datastore" on an unseeded id) -- this PUTs one
    # via the FHIR REST data plane.
    body = json.dumps(
        {
            "resourceType": "Patient",
            "id": patient_id,
            "identifier": [{"value": patient_id}],
            "name": [{"family": "Simparity", "given": ["Sim2real"]}],
            "gender": "female",
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


def _job_kwargs(domain_id: str, client_token: str, patient_id: str, fhir_endpoint: str, bucket: str) -> dict:
    return {
        "domainId": domain_id,
        "clientToken": client_token,
        "patientContext": {"patientId": patient_id, "dateOfBirth": _DATE_OF_BIRTH, "pronouns": "SHE_HER"},
        "insightsContext": {"insightsType": "PRE_VISIT"},
        "encounterContext": {"encounterReason": "Annual checkup"},
        "userContext": {"role": "CLINICIAN", "userId": "sim2real-user-1", "specialty": "PRIMARY_CARE"},
        "inputDataConfig": {
            "fhirServer": {"fhirEndpoint": fhir_endpoint},
            "s3Sources": [{"uri": f"s3://{bucket}/input.json"}],
        },
        "outputDataConfig": {"s3OutputPath": f"s3://{bucket}/output/"},
    }


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """StartPatientInsightsJob on a real FHIR patient completes SUCCEEDED, and its insights output
    object in S3 holds a generated clinical summary naming that patient."""
    ch = ctx.client("connecthealth")
    s3 = ctx.client("s3")
    hl = ctx.client("healthlake")

    bucket = ctx.unique_name("sim2real-conh-bkt-")
    _create_bucket(ctx, s3, bucket)

    def _delete_bucket():
        # the accepted job writes its output under the bucket, so empty every key, not just input.json
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_delete_bucket)

    fhir_endpoint = _create_fhir_datastore(ctx, hl, ctx.unique_name("sim2real-conh-hl-"))
    patient_id = ctx.unique_name("sim2real-patient-")
    _seed_patient(ctx, hl, fhir_endpoint, patient_id)

    domain_id = _create_domain(ch, ctx.unique_name("sim2real-conh-dom-"))["domainId"]
    ctx.on_cleanup(lambda: ch.delete_domain(domainId=domain_id))

    # HealthLake's FHIR search index can lag a freshly-written Patient by a short window.
    token = ctx.unique_name("sim2real-conh-tok-")
    job = None
    deadline = time.monotonic() + 90.0
    while job is None:
        try:
            job = ch.start_patient_insights_job(**_job_kwargs(domain_id, token, patient_id, fhir_endpoint, bucket))
        except ClientError as err:
            msg = err.response["Error"].get("Message", "")
            if err.response["Error"]["Code"] != "ValidationException" or "Patient could not be found" not in msg:
                raise
            if time.monotonic() > deadline:
                raise AssertionError(f"job never saw the FHIR Patient become visible: {err}") from err
            time.sleep(2.0)
    job_id = job["jobId"]
    assert job_id, f"expected a jobId from StartPatientInsightsJob, got {job!r}"

    # terminal state plus an invariant: the job reaches SUCCEEDED (never FAILED) and names an output.
    deadline = time.monotonic() + 180.0
    got = ch.get_patient_insights_job(domainId=domain_id, jobId=job_id)
    while got["jobStatus"] not in ("SUCCEEDED", "FAILED"):
        if time.monotonic() > deadline:
            raise AssertionError(f"job {job_id} did not reach a terminal state within 180s: {got!r}")
        time.sleep(3.0)
        got = ch.get_patient_insights_job(domainId=domain_id, jobId=job_id)
    assert got["jobStatus"] == "SUCCEEDED", (
        f"expected the job to SUCCEED, got {got['jobStatus']!r} (statusDetails {got.get('statusDetails')!r})"
    )
    output_uri = got.get("insightsOutput", {}).get("uri")
    assert output_uri, f"expected a SUCCEEDED job to carry insightsOutput.uri, got {got!r}"
    assert got["patientContext"]["patientId"] == patient_id, (
        f"expected the terminal job to still name patient {patient_id!r}, got {got['patientContext']!r}"
    )

    # the service's actual work product: fetch the generated summary and assert its content.
    parsed = urlsplit(output_uri)
    assert parsed.scheme == "s3" and parsed.netloc == bucket, (
        f"expected insightsOutput.uri to point into bucket {bucket!r}, got {output_uri!r}"
    )
    output_key = parsed.path.lstrip("/")
    obj = s3.get_object(Bucket=bucket, Key=output_key)
    summary = json.loads(obj["Body"].read())

    assert summary["TotalCount"] == 1, f"expected TotalCount 1, got {summary.get('TotalCount')!r}"
    patient_summaries = summary["PatientSummaries"]
    assert len(patient_summaries) == 1, f"expected exactly 1 PatientSummary, got {len(patient_summaries)}"
    patient_summary = patient_summaries[0]["PatientSummary"]
    assert patient_summary["PatientId"] == patient_id, (
        f"expected the summary to name patient {patient_id!r}, got {patient_summary.get('PatientId')!r}"
    )
    assert patient_summary["SummaryType"] == "Pre-visit", (
        f"expected SummaryType 'Pre-visit' for a PRE_VISIT job, got {patient_summary.get('SummaryType')!r}"
    )
    sections = patient_summary["Sections"]
    assert sections, f"expected at least one summary Section, got {sections!r}"
    narrative_texts = [
        entry["Text"]
        for section in sections
        for entry in section.get("ClinicalNarrative", [])
        if entry.get("Text", "").strip()
    ]
    assert narrative_texts, f"expected at least one non-empty ClinicalNarrative Text, got sections {sections!r}"

    # effect isolation: an independent read confirms the job is still there and still SUCCEEDED
    still = ch.get_patient_insights_job(domainId=domain_id, jobId=job_id)
    assert still["jobId"] == job_id and still["jobStatus"] == "SUCCEEDED", (
        f"expected the job to remain readable and SUCCEEDED, got {still!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
