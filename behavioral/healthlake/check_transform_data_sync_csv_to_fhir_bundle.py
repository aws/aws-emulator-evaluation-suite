"""transform-data-sync-csv-to-fhir-bundle."""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request

import botocore.auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transform-data-sync-csv-to-fhir-bundle"
GROUP = "data-plane"
SERVICES = ["healthlake"]

_YAML_PROFILE = """sourceSystemId: sim2real
tables:
  - tableName: patients
    primaryKeyColumn: PAT_ID
    resourceMappings:
      - targetResourceType: Patient
        fieldMappings:
          - fhirPath: name[0].family
            sourceColumn: LAST_NM
            transform:
              type: direct
          - fhirPath: name[0].given[0]
            sourceColumn: FIRST_NM
            transform:
              type: direct
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """TransformData's synchronous CSV->FHIR conversion applies the profile's YAML column mapping and returns a FHIR Bundle."""
    healthlake = ctx.client("healthlake")
    profile_name = ctx.unique_name("sim2real-csv-profile-")

    created = healthlake.create_data_transformation_profile(
        SourceFormat="CSV",
        ProfileName=profile_name,
        Source={"ProfileMapping": {"ProfileMapping": {"mapping-config.yaml": _YAML_PROFILE}}},
        Tags={"sim2real": CHECK},
    )
    profile_id = created["ProfileId"]

    def _cleanup():
        try:
            healthlake.delete_data_transformation_profile(ProfileId=profile_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    # two distinct rows: a target that echoes a canned bundle regardless of input
    # cannot produce both correct pairs, only one that actually applies the YAML
    # column mapping to each row can.
    request_body = json.dumps(
        {
            "ProfileId": profile_id,
            "InputData": {
                "CsvInput": {
                    "patients": "PAT_ID,LAST_NM,FIRST_NM\nP001,Smith,John\nP002,Jones,Amy"
                }
            },
        }
    ).encode()

    status, response = _datatransformation_request(
        ctx, healthlake, "POST", "/transform-data", request_body
    )
    assert status == 200, f"unexpected TransformData status {status}: {response}"

    bundle = json.loads(response["TransformedData"])
    assert bundle["resourceType"] == "Bundle", f"expected a Bundle, got {bundle.get('resourceType')}"
    patients = [
        entry["resource"]
        for entry in bundle.get("entry", [])
        if entry.get("resource", {}).get("resourceType") == "Patient"
    ]
    assert len(patients) == 2, f"expected exactly two Patient resources (one per CSV row), got {patients}"
    mapped_names = {(p["name"][0]["family"], p["name"][0]["given"][0]) for p in patients}
    expected_names = {("Smith", "John"), ("Jones", "Amy")}
    assert mapped_names == expected_names, (
        f"expected the CSV rows mapped via the YAML profile to produce family/given "
        f"pairs {expected_names}, got {mapped_names}"
    )

    # The profile this check created is now deleted, then proven gone via an
    # independent read at the destination -- GetDataTransformationProfile, a
    # different operation than both Create and TransformData.
    healthlake.delete_data_transformation_profile(ProfileId=profile_id)
    delete_read_code, delete_read_message = _error_code_and_message(
        lambda: healthlake.get_data_transformation_profile(ProfileId=profile_id)
    )
    assert delete_read_code == "ResourceNotFoundException", (
        f"expected the deleted profile {profile_id} to read back as "
        f"ResourceNotFoundException, got {delete_read_code}"
    )
    expected_message = f"Profile '{profile_id}' not found"
    assert delete_read_message == expected_message, (
        f"expected message {expected_message!r}, got {delete_read_message!r}"
    )


def _datatransformation_request(ctx, healthlake_client, method, path, body_bytes):
    """Send a SigV4-signed request to the region's datatransformation host; return (status, JSON body)."""
    base = ctx.service_url(f"https://datatransformation.healthlake.{ctx.region}.amazonaws.com")
    url = f"{base}{path}"

    creds = healthlake_client._request_signer._credentials
    headers = {"Content-Type": "application/json"}
    request = AWSRequest(method=method, url=url, data=body_bytes, headers=headers)
    botocore.auth.SigV4Auth(creds, "healthlake", ctx.region).add_auth(request)
    prepared_headers = dict(request.headers)
    req = urllib.request.Request(url, data=body_bytes, headers=prepared_headers, method=method)
    verify = ctx.http_verify
    tls = ssl.create_default_context(cafile=verify) if isinstance(verify, str) else None
    try:
        with urllib.request.urlopen(req, timeout=30, context=tls) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, {"raw": raw.decode(errors="replace")}


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
