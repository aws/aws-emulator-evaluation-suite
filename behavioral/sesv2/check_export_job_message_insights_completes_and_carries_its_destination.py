"""export-job-message-insights-completes-and-carries-its-destination."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from behavioral_harness import tags

CHECK = "export-job-message-insights-completes-and-carries-its-destination"
GROUP = "export-job"
SERVICES = ["sesv2"]

# CreateExportJob returns before the job has run; it progresses through CREATED/PROCESSING
# asynchronously.
_JOB_DEADLINE_S = 300.0
_JOB_INTERVAL_S = 5.0
_VDM_DEADLINE_S = 60.0
_VDM_INTERVAL_S = 3.0


@tags(
    "axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control",
    "resource:account-singleton:ses-account",
)
def run(ctx) -> None:
    """A MessageInsights export job COMPLETES and GetExportJob then reports a well-formed S3 URL
    and an ExportDataSource union with only the MessageInsights member populated.
    """
    ses = ctx.client("sesv2")
    original_vdm = ses.get_account().get("VdmAttributes", {}).get("VdmEnabled", "DISABLED")
    if original_vdm != "ENABLED":
        ses.put_account_vdm_attributes(VdmAttributes={"VdmEnabled": "ENABLED"})
        ctx.on_cleanup(
            lambda: ses.put_account_vdm_attributes(VdmAttributes={"VdmEnabled": original_vdm})
        )
        deadline = time.monotonic() + _VDM_DEADLINE_S
        observed = None
        while time.monotonic() < deadline:
            observed = ses.get_account().get("VdmAttributes", {}).get("VdmEnabled")
            if observed == "ENABLED":
                break
            time.sleep(_VDM_INTERVAL_S)
        else:
            raise AssertionError(
                f"account VdmEnabled never became ENABLED within {_VDM_DEADLINE_S}s "
                f"(last={observed!r}); a MessageInsights export cannot be created without it"
            )

    end = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    start = end - timedelta(days=1)
    job_id = ses.create_export_job(
        ExportDataSource={"MessageInsightsDataSource": {"StartDate": start, "EndDate": end}},
        ExportDestination={"DataFormat": "JSON"},
    )["JobId"]

    deadline = time.monotonic() + _JOB_DEADLINE_S
    final = None
    while time.monotonic() < deadline:
        final = ses.get_export_job(JobId=job_id)
        if final["JobStatus"] in ("COMPLETED", "FAILED", "CANCELLED"):
            break
        time.sleep(_JOB_INTERVAL_S)
    else:
        raise AssertionError(
            f"export job {job_id} never reached a terminal JobStatus within {_JOB_DEADLINE_S}s; "
            f"last was {final!r}"
        )

    assert final["JobStatus"] == "COMPLETED", (
        f"expected the MessageInsights export job to COMPLETE on an empty-history sandbox "
        f"account, got JobStatus={final['JobStatus']!r} (FailureInfo={final.get('FailureInfo')!r})"
    )
    assert final["ExportSourceType"] == "MESSAGE_INSIGHTS", (
        f"expected ExportSourceType 'MESSAGE_INSIGHTS', got {final.get('ExportSourceType')!r}"
    )

    data_source = final["ExportDataSource"]
    assert data_source.get("MessageInsightsDataSource") is not None, (
        f"a job created from a MessageInsightsDataSource reports a null MessageInsightsDataSource "
        f"member: {data_source!r}"
    )
    assert data_source.get("MetricsDataSource") is None, (
        f"a job created from a MessageInsightsDataSource ALSO reports a populated "
        f"MetricsDataSource member -- the union is not discriminating: {data_source!r}"
    )

    destination = final["ExportDestination"]
    assert destination["DataFormat"] == "JSON", (
        f"expected ExportDestination.DataFormat 'JSON', got {destination.get('DataFormat')!r}"
    )
    s3_url = destination.get("S3Url")
    assert s3_url, f"expected a non-blank ExportDestination.S3Url on a COMPLETED job, got {s3_url!r}"
    parsed = urlparse(s3_url)
    assert parsed.scheme in ("https", "s3"), (
        f"expected ExportDestination.S3Url to be an S3/HTTPS URL, got {s3_url!r}"
    )
    assert parsed.netloc, f"ExportDestination.S3Url has no host: {s3_url!r}"

    assert final.get("CreatedTimestamp") is not None, "expected a non-null CreatedTimestamp"
    assert final.get("CompletedTimestamp") is not None, "expected a non-null CompletedTimestamp"
    assert final["CompletedTimestamp"] >= final["CreatedTimestamp"], (
        f"CompletedTimestamp {final['CompletedTimestamp']!r} precedes CreatedTimestamp "
        f"{final['CreatedTimestamp']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
