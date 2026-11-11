"""metrics-export-presigned-url-serves-a-file-whose-shape-derives-from-the-request."""
from __future__ import annotations

import csv
import io
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metrics-export-presigned-url-serves-a-file-whose-shape-derives-from-the-request"
GROUP = "export-job"
SERVICES = ["sesv2"]

# SES metrics export is an asynchronous batch job whose only terminal signal is JobStatus; the two
# jobs process concurrently and share one deadline.
_EXPORT_DEADLINE_S = 420.0
_EXPORT_INTERVAL_S = 5.0
_VDM_DEADLINE_S = 60.0
# Requested by both jobs, so the two files describe the identical data source.
_REQUESTED_DIMENSIONS = {"ISP": ["*"]}
_REQUESTED_METRICS = [
    {"Name": "SEND", "Aggregation": "VOLUME"},
    {"Name": "DELIVERY", "Aggregation": "VOLUME"},
]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data", "resource:account-singleton:ses-account")
def run(ctx) -> None:
    """A COMPLETED metrics export's presigned S3 URL serves a CSV whose header names the requested
    dimension and metrics and whose rows match ExportedRecordsCount, a JSON export of the same
    source agrees on the count, and a one-character signature tamper is refused with HTTP 403.
    """
    sesv2 = ctx.client("sesv2")
    _ensure_vdm_enabled(ctx)

    end = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    start = end - timedelta(days=2)
    data_source = {
        "MetricsDataSource": {
            "Dimensions": _REQUESTED_DIMENSIONS,
            "Namespace": "VDM",
            "Metrics": _REQUESTED_METRICS,
            "StartDate": start,
            "EndDate": end,
        }
    }

    csv_job = sesv2.create_export_job(
        ExportDataSource=data_source, ExportDestination={"DataFormat": "CSV"}
    )["JobId"]
    json_job = sesv2.create_export_job(
        ExportDataSource=data_source, ExportDestination={"DataFormat": "JSON"}
    )["JobId"]
    assert csv_job != json_job, f"SES reused one JobId for two distinct export jobs: {csv_job}"

    # Both jobs were created before either is polled, so the deadline covers them concurrently.
    deadline = time.monotonic() + _EXPORT_DEADLINE_S
    csv_final = _await_completed(sesv2, csv_job, deadline)
    json_final = _await_completed(sesv2, json_job, deadline)

    for job_id, final, fmt in ((csv_job, csv_final, "CSV"), (json_job, json_final, "JSON")):
        destination = final["ExportDestination"]
        assert destination["DataFormat"] == fmt, (
            f"job {job_id} was created with DataFormat={fmt} but GetExportJob reports "
            f"{destination['DataFormat']!r}"
        )
        assert final["ExportSourceType"] == "METRICS_DATA", (
            f"job {job_id} was created from MetricsDataSource but GetExportJob reports "
            f"ExportSourceType={final['ExportSourceType']!r}"
        )
        assert "Statistics" in final, (
            f"COMPLETED job {job_id} carries no Statistics, so the exported record count cannot "
            f"be cross-checked against the file: keys={sorted(final)}"
        )
        assert "ExportedRecordsCount" in final["Statistics"], (
            f"COMPLETED job {job_id} Statistics has no ExportedRecordsCount: "
            f"{final['Statistics']!r}"
        )

    csv_url = _require_presigned_url(ctx, csv_final, csv_job)
    json_url = _require_presigned_url(ctx, json_final, json_job)

    # dp:endpoint — the export bytes are fetched over plain HTTPS with no SigV4 signing and no
    # boto3 client; the presigned URL is the only credential.
    csv_body = _fetch(ctx, csv_url)
    json_body = _fetch(ctx, json_url)

    csv_expected = final_count = csv_final["Statistics"]["ExportedRecordsCount"]
    json_expected = json_final["Statistics"]["ExportedRecordsCount"]

    assert csv_body.strip(), (
        f"the presigned CSV export for job {csv_job} served an empty body; a COMPLETED CSV export "
        f"must carry at least a header row (ExportedRecordsCount={csv_expected})"
    )
    header, csv_rows = _parse_csv(csv_body)
    _assert_header_covers_request(header)
    assert len(csv_rows) == csv_expected, (
        f"CSV export {csv_job} served {len(csv_rows)} data rows but the job reports "
        f"ExportedRecordsCount={csv_expected}; header={header!r}"
    )

    json_records = _parse_json_records(json_body, json_job)
    assert len(json_records) == json_expected, (
        f"JSON export {json_job} served {len(json_records)} records but the job reports "
        f"ExportedRecordsCount={json_expected}"
    )

    # Two serialisations of one data source over the same window must agree on the record count.
    assert csv_expected == json_expected, (
        f"the same MetricsDataSource exported as CSV and as JSON reported different record "
        f"counts: CSV job {csv_job} ExportedRecordsCount={csv_expected}, JSON job {json_job} "
        f"ExportedRecordsCount={json_expected}"
    )
    assert len(csv_rows) == len(json_records), (
        f"the same MetricsDataSource served {len(csv_rows)} CSV rows but {len(json_records)} JSON "
        f"records (expected equal); count reported by both jobs was {final_count}"
    )

    # The fetch above proves the URL serves bytes, so a one-character signature change must be
    # refused.
    tampered = _tamper_signature(csv_url)
    assert tampered != csv_url, "signature tampering produced an identical URL; the mutation is a no-op"
    status = _fetch_status(ctx, tampered)
    assert status == 403, (
        f"a presigned export URL with one character of X-Amz-Signature changed was answered with "
        f"HTTP {status}, expected 403; the URL served 200 unmutated, so it is not signature-scoped"
    )


def _ensure_vdm_enabled(ctx) -> None:
    """Enable account VDM, which metrics export requires, restoring the original on cleanup."""
    sesv2 = ctx.client("sesv2")
    account = sesv2.get_account()
    # GetAccount omits VdmAttributes on an account that never called PutAccountVdmAttributes.
    original = account.get("VdmAttributes", {}).get("VdmEnabled", "DISABLED")
    if original != "ENABLED":
        ctx.on_cleanup(
            lambda: sesv2.put_account_vdm_attributes(VdmAttributes={"VdmEnabled": original})
        )
        sesv2.put_account_vdm_attributes(VdmAttributes={"VdmEnabled": "ENABLED"})

    # PutAccountVdmAttributes' effect is read back through a different operation (GetAccount).
    deadline = time.monotonic() + _VDM_DEADLINE_S
    last = None
    while time.monotonic() < deadline:
        last = sesv2.get_account()["VdmAttributes"].get("VdmEnabled")
        if last == "ENABLED":
            return
        time.sleep(2.0)
    raise AssertionError(
        f"account VdmEnabled never became ENABLED within {_VDM_DEADLINE_S}s (last={last!r}); "
        f"metrics export cannot be exercised without it"
    )


def _await_completed(sesv2, job_id: str, deadline: float) -> dict:
    """Poll GetExportJob until COMPLETED; raise on timeout or on FAILED/CANCELLED."""
    last = None
    while time.monotonic() < deadline:
        last = sesv2.get_export_job(JobId=job_id)
        status = last["JobStatus"]
        if status == "COMPLETED":
            return last
        if status in ("FAILED", "CANCELLED"):
            raise AssertionError(
                f"export job {job_id} reached terminal status {status!r} instead of COMPLETED; "
                f"FailureInfo={last.get('FailureInfo')!r}"
            )
        time.sleep(_EXPORT_INTERVAL_S)
    raise AssertionError(
        f"export job {job_id} never reached COMPLETED before the shared "
        f"{_EXPORT_DEADLINE_S}s deadline (last={last!r})"
    )


def _require_presigned_url(ctx, final: dict, job_id: str) -> str:
    destination = final["ExportDestination"]
    assert "S3Url" in destination, (
        f"COMPLETED export job {job_id} carries no ExportDestination.S3Url, so the exported bytes "
        f"are unreachable: {destination!r}"
    )
    url = destination["S3Url"]
    parsed = urllib.parse.urlparse(url)
    assert not (p := ctx.published_url_mismatch(url)), p
    query = urllib.parse.parse_qs(parsed.query)
    assert "X-Amz-Signature" in query, (
        f"export job {job_id} S3Url carries no X-Amz-Signature, so it is not a presigned URL and "
        f"the object is either public or unreachable: query keys={sorted(query)}"
    )
    return url


def _fetch(ctx, url: str) -> str:
    target_url, route_headers = ctx.endpoint_route(url)
    with urllib.request.urlopen(urllib.request.Request(target_url, headers=route_headers), timeout=60) as response:  # noqa: S310 - https URL from SES
        assert response.status == 200, f"presigned export fetch returned HTTP {response.status}"
        return response.read().decode("utf-8")


def _fetch_status(ctx, url: str) -> int:
    try:
        target_url, route_headers = ctx.endpoint_route(url)
        with urllib.request.urlopen(urllib.request.Request(target_url, headers=route_headers), timeout=60) as response:  # noqa: S310
            return response.status
    except urllib.error.HTTPError as err:
        return err.code


def _tamper_signature(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    mutated = []
    for key, value in pairs:
        if key == "X-Amz-Signature":
            first = value[0]
            value = ("1" if first == "0" else "0") + value[1:]
        mutated.append((key, value))
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(mutated)))


def _parse_csv(body: str) -> tuple[list[str], list[list[str]]]:
    rows = [row for row in csv.reader(io.StringIO(body)) if any(cell.strip() for cell in row)]
    assert rows, f"CSV export body parsed to zero rows: {body[:200]!r}"
    return rows[0], rows[1:]


def _normalise(token: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", token.upper())


def _assert_header_covers_request(header: list[str]) -> None:
    """Assert the CSV header names every requested dimension and metric; derived from the request
    because no doc states SES's exact export column titles."""
    normalised = [_normalise(cell) for cell in header]
    joined = "|".join(normalised)
    for dimension in _REQUESTED_DIMENSIONS:
        assert _normalise(dimension) in joined, (
            f"requested export dimension {dimension!r} is named by no CSV header column; "
            f"header={header!r}"
        )
    for metric in _REQUESTED_METRICS:
        assert _normalise(metric["Name"]) in joined, (
            f"requested export metric {metric['Name']!r} is named by no CSV header column; "
            f"header={header!r}"
        )


def _parse_json_records(body: str, job_id: str) -> list:
    text = body.strip()
    assert text, (
        f"the presigned JSON export for job {job_id} served an empty body; a COMPLETED export "
        f"must serve a parseable document"
    )
    try:
        loaded = json.loads(text)
    except ValueError:
        loaded = None
    if isinstance(loaded, list):
        return loaded
    if isinstance(loaded, dict):
        return [loaded]
    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except ValueError as err:
            raise AssertionError(
                f"JSON export {job_id} is neither a JSON array/object nor JSON-lines; line "
                f"{line[:120]!r} failed to parse ({err})"
            ) from err
    assert records, (
        f"JSON export {job_id} served a non-empty body that yielded no records: {text[:200]!r}"
    )
    return records


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
