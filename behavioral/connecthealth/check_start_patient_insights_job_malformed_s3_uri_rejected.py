"""start-patient-insights-job-malformed-s3-uri-rejected."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

import botocore.auth
from behavioral_harness import tags
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

CHECK = "start-patient-insights-job-malformed-s3-uri-rejected"
GROUP = "overly-permissive"
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


def _base_kwargs(domain_id: str, client_token: str, patient_id: str) -> dict:
    return {
        "domainId": domain_id,
        "clientToken": client_token,
        "patientContext": {"patientId": patient_id, "dateOfBirth": "1990-01-01", "pronouns": "HE_HIM"},
        "insightsContext": {"insightsType": "PRE_VISIT"},
        "encounterContext": {"encounterReason": "Annual checkup"},
        "userContext": {"role": "CLINICIAN", "userId": "sim2real-user-1", "specialty": "PRIMARY_CARE"},
    }


def _fhir_input_data_config(fhir_endpoint: str, bucket: str) -> dict:
    return {
        "fhirServer": {"fhirEndpoint": fhir_endpoint},
        "s3Sources": [{"uri": f"s3://{bucket}/input.json"}],
    }


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
    # correctly shaped.
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """StartPatientInsightsJob rejects an OutputDataConfig.S3OutputPath that is not an s3:// URI and never creates a job for that request."""
    ch = ctx.client("connecthealth")
    s3 = ctx.client("s3")
    hl = ctx.client("healthlake")
    domain_id = _create_domain(ch, ctx.unique_name("sim2real-conh-dom-"))["domainId"]
    ctx.on_cleanup(lambda: ch.delete_domain(domainId=domain_id))
    bucket = ctx.unique_name("sim2real-conh-bkt-")
    _create_bucket(ctx, s3, bucket)
    fhir_endpoint = _create_fhir_datastore(ctx, hl, ctx.unique_name("sim2real-conh-hl-"))
    patient_id = ctx.unique_name("sim2real-patient-")
    _seed_patient(ctx, hl, fhir_endpoint, patient_id)

    # positive control: a syntactically valid s3:// output path is accepted
    ok_kwargs = _base_kwargs(domain_id, ctx.unique_name("sim2real-conh-tok-"), patient_id)
    ok_kwargs["inputDataConfig"] = _fhir_input_data_config(fhir_endpoint, bucket)
    ok_kwargs["outputDataConfig"] = {"s3OutputPath": f"s3://{bucket}/output/"}
    ok = ch.start_patient_insights_job(**ok_kwargs)
    assert ok["jobId"], f"positive control did not return a jobId: {ok!r}"

    # negative: malformed S3 URI (no s3:// prefix) -> reaches the service, fails pattern validation
    bad_kwargs = _base_kwargs(domain_id, ctx.unique_name("sim2real-conh-tok-"), patient_id)
    bad_kwargs["inputDataConfig"] = _fhir_input_data_config(fhir_endpoint, bucket)
    bad_kwargs["outputDataConfig"] = {"s3OutputPath": "not-an-s3-uri"}
    code, message = _client_error(lambda: ch.start_patient_insights_job(**bad_kwargs))
    assert code == "ValidationException", f"expected ValidationException for malformed s3OutputPath, got {code!r}"
    assert message == "Request validation failed", f"expected 'Request validation failed', got {message!r}"

    # effect absent: no job was persisted under the rejected request's clientToken. If
    # StartPatientInsightsJob had created a job before failing validation, replaying the IDENTICAL
    # request (same token, same body) would idempotently return that job instead of failing
    # validation again.
    retry_code, retry_message = _client_error(lambda: ch.start_patient_insights_job(**bad_kwargs))
    assert retry_code == "ValidationException", (
        f"identical retry of the rejected request should re-fail validation (no job persisted under its "
        f"clientToken), got {retry_code!r}"
    )
    assert retry_message == "Request validation failed", f"expected 'Request validation failed', got {retry_message!r}"

    # service still healthy: a fresh, valid request right after the rejection still succeeds
    ok2_kwargs = _base_kwargs(domain_id, ctx.unique_name("sim2real-conh-tok-"), patient_id)
    ok2_kwargs["inputDataConfig"] = _fhir_input_data_config(fhir_endpoint, bucket)
    ok2_kwargs["outputDataConfig"] = {"s3OutputPath": f"s3://{bucket}/output2/"}
    ok2 = ch.start_patient_insights_job(**ok2_kwargs)
    assert ok2["jobId"] and ok2["jobId"] != ok["jobId"], (
        f"fresh valid request after the rejection should get a new jobId, got {ok2.get('jobId')!r} vs {ok['jobId']!r}"
    )

    # terminal read: an independent GetPatientInsightsJob call (not the StartPatientInsightsJob response
    # itself) confirms the post-rejection job is real and registered, not just an echoed request id
    got2 = ch.get_patient_insights_job(domainId=domain_id, jobId=ok2["jobId"])
    assert got2["jobId"] == ok2["jobId"], f"independent read returned {got2.get('jobId')!r}, expected {ok2['jobId']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
