"""fhir-rest-api-native-protocol-roundtrip."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

import botocore.auth
from botocore.awsrequest import AWSRequest

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "fhir-rest-api-native-protocol-roundtrip"
GROUP = "data-plane"
SERVICES = ["healthlake"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """FHIR create+read interactions against a real HealthLake DatastoreEndpoint over the FHIR REST wire protocol."""
    healthlake = ctx.client("healthlake")
    name = ctx.unique_name("sim2real-hl-native-")

    created = healthlake.create_fhir_datastore(
        DatastoreName=name,
        DatastoreTypeVersion="R4",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    datastore_id = created["DatastoreId"]

    def _cleanup():
        try:
            healthlake.delete_fhir_datastore(DatastoreId=datastore_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    props = _poll_until(
        lambda: healthlake.describe_fhir_datastore(DatastoreId=datastore_id)["DatastoreProperties"],
        lambda p: p["DatastoreStatus"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=2100.0,
        interval_s=20.0,
    )
    assert props["DatastoreStatus"] == "ACTIVE", f"datastore reached {props['DatastoreStatus']}"

    endpoint = props["DatastoreEndpoint"].rstrip("/")

    patient_body = json.dumps(
        {
            "resourceType": "Patient",
            "identifier": [{"system": "urn:sim2real:test", "value": "sim2real-native-001"}],
            "name": [{"family": "SimparitySurname", "given": ["Native"]}],
            "gender": "unknown",
        }
    ).encode()

    status, created_patient = _signed_request(
        ctx, healthlake, "POST", f"{endpoint}/Patient", body_bytes=patient_body
    )
    assert status == 201, f"unexpected create status {status}: {created_patient}"
    assert created_patient["resourceType"] == "Patient", f"expected resourceType Patient, got {created_patient.get('resourceType')}"
    patient_id = created_patient["id"]
    assert created_patient["name"][0]["family"] == "SimparitySurname", (
        f"expected family name SimparitySurname in create response, got {created_patient['name'][0].get('family')}"
    )

    status, fetched_patient = _signed_request(ctx, healthlake, "GET", f"{endpoint}/Patient/{patient_id}")
    assert status == 200, f"unexpected read status {status}: {fetched_patient}"
    assert fetched_patient["resourceType"] == "Patient", f"expected resourceType Patient, got {fetched_patient.get('resourceType')}"
    assert fetched_patient["id"] == patient_id, f"expected id {patient_id}, got {fetched_patient.get('id')}"
    assert fetched_patient["name"][0]["family"] == "SimparitySurname", (
        f"expected family name SimparitySurname on independent read, got {fetched_patient['name'][0].get('family')}"
    )
    assert fetched_patient["identifier"][0]["value"] == "sim2real-native-001", (
        f"expected identifier value sim2real-native-001 on independent read, got {fetched_patient['identifier'][0].get('value')}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed={last!r}")


def _signed_request(ctx, healthlake_client, method, url, body_bytes=b""):
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
