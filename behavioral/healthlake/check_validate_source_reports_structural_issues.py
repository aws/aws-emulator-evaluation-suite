"""validate-source-reports-structural-issues."""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request

import botocore.auth
from botocore.awsrequest import AWSRequest

from behavioral_harness import tags

CHECK = "validate-source-reports-structural-issues"
GROUP = "data-plane"
SERVICES = ["healthlake"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """ValidateSource answers 200 with Valid=True and no errors for a complete C-CDA document, 200
    with Valid=False and issues for an incomplete one and for unparseable bytes (a CRITICAL_ERROR
    issue), and 400 for the unsupported CSV source format."""
    healthlake = ctx.client("healthlake")

    # positive control: a structurally complete CCD (US Realm Header + CCD templateIds, patient,
    # author, custodian, one populated section with a coded entry) -- without this, "reports
    # structural issues" is indistinguishable from "always reports Valid=False for any CCDA".
    valid_ccda = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<ClinicalDocument xmlns="urn:hl7-org:v3" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        b'<realmCode code="US"/>'
        b'<typeId root="2.16.840.1.113883.1.3" extension="POCD_HD000040"/>'
        b'<templateId root="2.16.840.1.113883.10.20.22.1.1" extension="2015-08-01"/>'
        b'<templateId root="2.16.840.1.113883.10.20.22.1.2" extension="2015-08-01"/>'
        b'<id root="1.2.3.4.5.6.7.8.9" extension="TT988"/>'
        b'<code code="34133-9" codeSystem="2.16.840.1.113883.6.1" displayName="Summary of episode note"/>'
        b'<title>Continuity of Care Document</title>'
        b'<effectiveTime value="20260101120000+0000"/>'
        b'<confidentialityCode code="N" codeSystem="2.16.840.1.113883.5.25"/>'
        b'<languageCode code="en-US"/>'
        b'<recordTarget><patientRole>'
        b'<id extension="12345" root="2.16.840.1.113883.19.5"/>'
        b'<patient><name><given>John</given><family>Doe</family></name>'
        b'<administrativeGenderCode code="M" codeSystem="2.16.840.1.113883.5.1"/>'
        b'<birthTime value="19700101"/></patient>'
        b'</patientRole></recordTarget>'
        b'<author><time value="20260101120000+0000"/><assignedAuthor>'
        b'<id extension="99999" root="2.16.840.1.113883.19.5"/>'
        b'<assignedPerson><name><given>Jane</given><family>Smith</family></name></assignedPerson>'
        b'</assignedAuthor></author>'
        b'<custodian><assignedCustodian><representedCustodianOrganization>'
        b'<id extension="99999" root="2.16.840.1.113883.19.5"/><name>Test Hospital</name>'
        b'</representedCustodianOrganization></assignedCustodian></custodian>'
        b'<component><structuredBody><component><section>'
        b'<templateId root="2.16.840.1.113883.10.20.22.2.5.1" extension="2015-08-01"/>'
        b'<code code="11450-4" codeSystem="2.16.840.1.113883.6.1" displayName="Problem List"/>'
        b'<title>Problems</title><text>Hypertension.</text>'
        b'<entry><act classCode="ACT" moodCode="EVN">'
        b'<templateId root="2.16.840.1.113883.10.20.22.4.3" extension="2015-08-01"/>'
        b'<id root="ec8a6ff8-ed4b-4f7e-82c3-e98e58b45de7"/>'
        b'<code nullFlavor="NA"/><statusCode code="active"/>'
        b'<effectiveTime><low value="20200101"/></effectiveTime>'
        b'<entryRelationship typeCode="SUBJ">'
        b'<observation classCode="OBS" moodCode="EVN">'
        b'<templateId root="2.16.840.1.113883.10.20.22.4.4" extension="2015-08-01"/>'
        b'<id root="ab1791b0-5c71-11db-b0de-0800200c9a66"/>'
        b'<code code="55607006" codeSystem="2.16.840.1.113883.6.96" displayName="Problem"/>'
        b'<statusCode code="completed"/><effectiveTime><low value="20200101"/></effectiveTime>'
        b'<value xsi:type="CD" code="38341003" codeSystem="2.16.840.1.113883.6.96" displayName="Hypertension"/>'
        b'</observation></entryRelationship></act></entry>'
        b'</section></component></structuredBody></component>'
        b'</ClinicalDocument>'
    )
    status, valid_result = _validate_source_request(ctx, healthlake, "CCDA", valid_ccda)
    assert status == 200, f"unexpected ValidateSource status {status}: {valid_result}"
    assert valid_result["Valid"] is True, f"expected a structurally complete CCDA to validate, got {valid_result}"
    assert valid_result["Summary"]["ErrorCount"] == 0, f"expected zero errors for a valid CCDA, got {valid_result['Summary']}"

    # well-formed XML (so it parses) but missing required C-CDA structure (no templateId,
    # no required sections) -> a structural/conformance failure, not a parse failure.
    incomplete_ccda = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<ClinicalDocument xmlns="urn:hl7-org:v3"></ClinicalDocument>'
    )
    status, invalid_result = _validate_source_request(ctx, healthlake, "CCDA", incomplete_ccda)
    assert status == 200, f"unexpected ValidateSource status {status}: {invalid_result}"
    assert invalid_result["Valid"] is False
    assert invalid_result["SourceFormat"] == "CCDA"
    assert invalid_result["Summary"]["ErrorCount"] >= 1
    assert len(invalid_result["Issues"]) >= 1

    # a second distinct malformed-input case: bytes that aren't XML at all still surface
    # as a soft (200, Valid=False) structural finding rather than throwing -- ValidateSource's
    # contract is "always 200 with a validation report" for content-level problems; only a
    # request-level problem (like an unsupported sourceFormat, tested below) is a hard error.
    garbage = b"this is definitely not a C-CDA clinical document, just plain garbage bytes"
    status, garbage_result = _validate_source_request(ctx, healthlake, "CCDA", garbage)
    assert status == 200, f"unexpected ValidateSource status {status}: {garbage_result}"
    assert garbage_result["Valid"] is False
    assert garbage_result["Summary"]["ErrorCount"] >= 1
    assert any(issue["Code"] == "CRITICAL_ERROR" for issue in garbage_result["Issues"])

    # overly-permissive boundary #2: ValidateSource only screens C-CDA; a CSV sourceFormat
    # must be rejected outright rather than silently accepted/validated.
    well_formed_csv = b"PAT_ID,LAST_NM,FIRST_NM\nP001,Smith,John\n"
    status, csv_result = _validate_source_request(ctx, healthlake, "CSV", well_formed_csv)
    assert status == 400, f"expected ValidateSource to reject CSV sourceFormat, got {status}: {csv_result}"


def _validate_source_request(ctx, healthlake_client, source_format, body_bytes):
    # ValidateSource is not in the SDK model: it is served on the region's datatransformation
    # host, the endpoint the client's modelled data-transformation operations address.
    base = ctx.service_url(f"https://datatransformation.healthlake.{ctx.region}.amazonaws.com")
    url = f"{base}/validate-source?sourceFormat={source_format}"

    creds = healthlake_client._request_signer._credentials
    headers = {"Content-Type": "application/octet-stream"}
    request = AWSRequest(method="POST", url=url, data=body_bytes, headers=headers)
    botocore.auth.SigV4Auth(creds, "healthlake", ctx.region).add_auth(request)
    prepared_headers = dict(request.headers)
    req = urllib.request.Request(url, data=body_bytes, headers=prepared_headers, method="POST")
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
