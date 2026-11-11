"""list-export-jobs-filters-partition-the-jobs-this-check-created."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "list-export-jobs-filters-partition-the-jobs-this-check-created"
GROUP = "export-job"
SERVICES = ["sesv2"]

_VDM_DEADLINE_S = 60.0
_VDM_INTERVAL_S = 3.0
# A job's status advances asynchronously, so GetExportJob and ListExportJobs(JobStatus=) can
# straddle a transition; retry until one consistent observation.
_CONSISTENCY_DEADLINE_S = 90.0
_CONSISTENCY_INTERVAL_S = 3.0
_ALL_SOURCE_TYPES = ("METRICS_DATA", "MESSAGE_INSIGHTS")


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:ses-account")
def run(ctx) -> None:
    """ListExportJobs' ExportSourceType and JobStatus filters partition two jobs from different data
    sources: each lists under its own type and the status GetExportJob reports, and filters AND.

    Reference: https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_ListExportJobs.html
    """
    sesv2 = ctx.client("sesv2")
    _ensure_vdm_enabled(ctx)

    end = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    start = end - timedelta(days=2)

    # Export jobs cannot be deleted, so no cleanup is registered for them.
    metrics_job = sesv2.create_export_job(
        ExportDataSource={
            "MetricsDataSource": {
                "Dimensions": {"ISP": ["*"]},
                "Namespace": "VDM",
                "Metrics": [{"Name": "SEND", "Aggregation": "VOLUME"}],
                "StartDate": start,
                "EndDate": end,
            }
        },
        ExportDestination={"DataFormat": "CSV"},
    )["JobId"]
    insights_job = sesv2.create_export_job(
        ExportDataSource={"MessageInsightsDataSource": {"StartDate": start, "EndDate": end}},
        ExportDestination={"DataFormat": "JSON"},
    )["JobId"]
    assert metrics_job != insights_job, (
        f"SES returned one JobId {metrics_job} for two export jobs created from different data "
        f"sources"
    )

    expected = {
        metrics_job: ("METRICS_DATA", "CSV"),
        insights_job: ("MESSAGE_INSIGHTS", "JSON"),
    }

    # Each job reports the source type derived from the union member that was populated.
    for job_id, (source_type, data_format) in expected.items():
        described = sesv2.get_export_job(JobId=job_id)
        assert described["ExportSourceType"] == source_type, (
            f"job {job_id} was created from a {source_type} data source but GetExportJob reports "
            f"ExportSourceType={described['ExportSourceType']!r}"
        )
        assert described["ExportDestination"]["DataFormat"] == data_format, (
            f"job {job_id} was created with DataFormat={data_format} but GetExportJob reports "
            f"{described['ExportDestination']['DataFormat']!r}"
        )

    # The ExportSourceType filter partitions the two jobs exactly: each is present under its own
    # type and absent under the other.
    listings = {
        source_type: _list_ids(sesv2, ExportSourceType=source_type)
        for source_type in _ALL_SOURCE_TYPES
    }
    for job_id, (source_type, _fmt) in expected.items():
        other = next(t for t in _ALL_SOURCE_TYPES if t != source_type)
        assert job_id in listings[source_type], (
            f"job {job_id} has ExportSourceType={source_type} but does not appear in "
            f"ListExportJobs(ExportSourceType={source_type})"
        )
        assert job_id not in listings[other], (
            f"job {job_id} has ExportSourceType={source_type} but ListExportJobs("
            f"ExportSourceType={other}) also returned it, so the filter is not applied"
        )

    # The JobStatus filter agrees with the target's own reported status, and composes with
    # ExportSourceType as AND.
    for job_id, (source_type, _fmt) in expected.items():
        status, by_status, by_both, by_wrong_type = _consistent_status_observation(
            sesv2, job_id, source_type
        )
        assert job_id in by_status, (
            f"GetExportJob reports job {job_id} as {status!r} but "
            f"ListExportJobs(JobStatus={status}) does not return it"
        )
        assert job_id in by_both, (
            f"job {job_id} is {source_type}/{status} but ListExportJobs(ExportSourceType="
            f"{source_type}, JobStatus={status}) does not return it, so the two filters do not "
            f"compose as AND"
        )
        other = next(t for t in _ALL_SOURCE_TYPES if t != source_type)
        assert job_id not in by_wrong_type, (
            f"job {job_id} is {source_type}/{status} but ListExportJobs(ExportSourceType={other}, "
            f"JobStatus={status}) returned it, so the filters are being OR-ed rather than AND-ed"
        )


def _ensure_vdm_enabled(ctx) -> None:
    """Enable account-wide VDM (required for metrics export) and restore the original setting.

    GetAccount omits VdmAttributes when VDM was never configured; absence means DISABLED.
    """
    sesv2 = ctx.client("sesv2")
    original = sesv2.get_account().get("VdmAttributes", {}).get("VdmEnabled", "DISABLED")
    if original != "ENABLED":
        ctx.on_cleanup(
            lambda: sesv2.put_account_vdm_attributes(VdmAttributes={"VdmEnabled": original})
        )
        sesv2.put_account_vdm_attributes(VdmAttributes={"VdmEnabled": "ENABLED"})

    deadline = time.monotonic() + _VDM_DEADLINE_S
    observed = None
    while time.monotonic() < deadline:
        observed = sesv2.get_account().get("VdmAttributes", {}).get("VdmEnabled")
        if observed == "ENABLED":
            return
        time.sleep(_VDM_INTERVAL_S)
    raise AssertionError(
        f"account VdmEnabled never became ENABLED within {_VDM_DEADLINE_S}s (last={observed!r}); "
        f"metrics export cannot be created without it"
    )


def _list_ids(sesv2, **filters) -> set[str]:
    ids: set[str] = set()
    token = None
    while True:
        kwargs = dict(filters)
        if token:
            kwargs["NextToken"] = token
        page = sesv2.list_export_jobs(**kwargs)
        for job in page.get("ExportJobs", []):
            ids.add(job["JobId"])
        token = page.get("NextToken")
        if not token:
            break
    return ids


def _consistent_status_observation(sesv2, job_id: str, source_type: str):
    """Read a job's status and its three status-filtered listings with no transition in between.

    Retries, and raises rather than return an inconsistent reading."""
    other = next(t for t in _ALL_SOURCE_TYPES if t != source_type)
    deadline = time.monotonic() + _CONSISTENCY_DEADLINE_S
    last = None
    while time.monotonic() < deadline:
        status = sesv2.get_export_job(JobId=job_id)["JobStatus"]
        by_status = _list_ids(sesv2, JobStatus=status)
        by_both = _list_ids(sesv2, ExportSourceType=source_type, JobStatus=status)
        by_wrong_type = _list_ids(sesv2, ExportSourceType=other, JobStatus=status)
        recheck = sesv2.get_export_job(JobId=job_id)["JobStatus"]
        if recheck == status:
            return status, by_status, by_both, by_wrong_type
        last = (status, recheck)
        time.sleep(_CONSISTENCY_INTERVAL_S)
    raise AssertionError(
        f"job {job_id} kept transitioning across every attempt to observe its status and the "
        f"status-filtered listings together within {_CONSISTENCY_DEADLINE_S}s (last pair={last!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
