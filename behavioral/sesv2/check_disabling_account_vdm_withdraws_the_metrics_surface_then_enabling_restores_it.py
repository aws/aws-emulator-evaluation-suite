"""disabling-account-vdm-withdraws-the-metrics-surface-then-enabling-restores-it."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disabling-account-vdm-withdraws-the-metrics-surface-then-enabling-restores-it"
GROUP = "account-v2"
SERVICES = ["sesv2"]

# PutAccountVdmAttributes is an account-level write observed through other operations.
# VdmEnabled is one value per account per region, and this check disables it mid-run.
_VDM_DEADLINE_S = 90.0
_VDM_INTERVAL_S = 3.0
_QUERY_ID = "vdm-gate-probe"


@tags("axis:rejection", "cap:c1", "concern:metrics", "concern:negative-classes", "plane:control", "resource:account-singleton:ses-account")
def run(ctx) -> None:
    """With VdmEnabled=DISABLED, BatchGetMetricData (NotFoundException) and a MetricsDataSource
    CreateExportJob (BadRequestException, no job created) are refused; ENABLED makes both succeed.
    """
    sesv2 = ctx.client("sesv2")
    original = _original_vdm_state(sesv2)
    ctx.on_cleanup(
        lambda: sesv2.put_account_vdm_attributes(VdmAttributes={"VdmEnabled": original})
    )

    # Beat 1 — positive control with VDM on.
    _set_vdm(sesv2, "ENABLED")
    enabled_metrics = sesv2.batch_get_metric_data(Queries=[_metric_query()])
    _assert_query_answered(enabled_metrics, "with VdmEnabled=ENABLED")

    before_ids = _metrics_job_ids(sesv2)
    enabled_job = sesv2.create_export_job(
        ExportDataSource=_metrics_data_source(), ExportDestination={"DataFormat": "CSV"}
    )["JobId"]
    described = sesv2.get_export_job(JobId=enabled_job)
    assert described["ExportSourceType"] == "METRICS_DATA", (
        f"positive control: job {enabled_job} was created from MetricsDataSource but GetExportJob "
        f"reports ExportSourceType={described['ExportSourceType']!r}"
    )
    assert enabled_job not in before_ids, (
        f"CreateExportJob returned JobId {enabled_job}, which ListExportJobs already reported before "
        f"the call, so no new job was created"
    )
    after_enabled_ids = _metrics_job_ids(sesv2)
    assert enabled_job in after_enabled_ids, (
        f"positive control: job {enabled_job} was created but does not appear in "
        f"ListExportJobs(ExportSourceType=METRICS_DATA); listed={sorted(after_enabled_ids)[:10]}"
    )

    # Beat 2 — break exactly one thing, and read the break back on a different operation.
    _set_vdm(sesv2, "DISABLED")

    # Beat 3 — the specific refusals.
    baseline_ids = _metrics_job_ids(sesv2)
    export_code = _error_code(
        lambda: sesv2.create_export_job(
            ExportDataSource=_metrics_data_source(), ExportDestination={"DataFormat": "CSV"}
        )
    )
    metrics_code = _error_code(lambda: sesv2.batch_get_metric_data(Queries=[_metric_query()]))
    vdm_off = "To use this feature you must enable Virtual Deliverability Manager"
    assert export_code == ("BadRequestException", vdm_off), (
        f"CreateExportJob(MetricsDataSource) with VdmEnabled=DISABLED returned {export_code!r}, "
        f"expected BadRequestException; the identical call with VDM enabled created job "
        f"{enabled_job}"
    )
    assert metrics_code == ("NotFoundException", vdm_off), (
        f"BatchGetMetricData with VdmEnabled=DISABLED returned {metrics_code!r}, expected "
        f"NotFoundException; the identical query with VDM enabled was answered"
    )

    # Beat 4 — effect absent: the refused create left no job behind.
    assert _metrics_job_ids(sesv2) == baseline_ids, (
        "the refused CreateExportJob still created a METRICS_DATA export job: the id set changed "
        "from the pre-refusal snapshot"
    )

    # Beats 5 and 6 — restore, and demand the identical calls succeed.
    _set_vdm(sesv2, "ENABLED")
    restored_metrics = sesv2.batch_get_metric_data(Queries=[_metric_query()])
    _assert_query_answered(restored_metrics, "after VdmEnabled was restored to ENABLED")
    restored_job = sesv2.create_export_job(
        ExportDataSource=_metrics_data_source(), ExportDestination={"DataFormat": "CSV"}
    )["JobId"]
    assert restored_job != enabled_job, (
        f"the restored CreateExportJob returned the same JobId {restored_job} as the positive "
        f"control, so no new job was created"
    )
    restored_ids = _metrics_job_ids(sesv2)
    assert restored_job in restored_ids, (
        f"job {restored_job}, created after VDM was re-enabled, does not appear in "
        f"ListExportJobs(ExportSourceType=METRICS_DATA)"
    )


def _original_vdm_state(sesv2) -> str:
    """The account's VdmEnabled, defaulting to DISABLED.

    GetAccount omits VdmAttributes entirely until the first PutAccountVdmAttributes call.
    """
    attributes = sesv2.get_account().get("VdmAttributes", {})
    return attributes.get("VdmEnabled", "DISABLED")


def _set_vdm(sesv2, target: str) -> None:
    sesv2.put_account_vdm_attributes(VdmAttributes={"VdmEnabled": target})
    deadline = time.monotonic() + _VDM_DEADLINE_S
    observed = None
    while time.monotonic() < deadline:
        observed = sesv2.get_account()["VdmAttributes"].get("VdmEnabled")
        if observed == target:
            return
        time.sleep(_VDM_INTERVAL_S)
    raise AssertionError(
        f"GetAccount never reported VdmEnabled={target!r} within {_VDM_DEADLINE_S}s of "
        f"PutAccountVdmAttributes (last={observed!r})"
    )


def _metrics_data_source() -> dict:
    end = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    return {
        "MetricsDataSource": {
            "Dimensions": {"ISP": ["*"]},
            "Namespace": "VDM",
            "Metrics": [{"Name": "SEND", "Aggregation": "VOLUME"}],
            "StartDate": end - timedelta(days=2),
            "EndDate": end,
        }
    }


def _metric_query() -> dict:
    """A one-day VDM query aligned to UTC midnight.

    BatchGetMetricData rejects partial-day intervals with BadRequestException.
    """
    end = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    return {
        "Id": _QUERY_ID,
        "Namespace": "VDM",
        "Metric": "SEND",
        "StartDate": end - timedelta(days=1),
        "EndDate": end,
    }


def _assert_query_answered(response: dict, phase: str) -> None:
    """Assert the query id lands in Results, not Errors."""
    errored = {entry["Id"] for entry in response.get("Errors", [])}
    answered = {entry["Id"] for entry in response.get("Results", [])}
    assert _QUERY_ID not in errored, (
        f"{phase}: BatchGetMetricData reported query {_QUERY_ID!r} in Errors: "
        f"{response.get('Errors')!r}"
    )
    assert _QUERY_ID in answered, (
        f"{phase}: BatchGetMetricData returned no Results entry for query {_QUERY_ID!r}; "
        f"answered={sorted(answered)}"
    )


def _metrics_job_ids(sesv2) -> set[str]:
    ids: set[str] = set()
    token = None
    while True:
        kwargs = {"ExportSourceType": "METRICS_DATA"}
        if token:
            kwargs["NextToken"] = token
        page = sesv2.list_export_jobs(**kwargs)
        for job in page.get("ExportJobs", []):
            ids.add(job["JobId"])
        token = page.get("NextToken")
        if not token:
            break
    return ids


def _error_code(fn) -> tuple[str, str]:
    """Return the ClientError (Code, Message); raise on unexpected success."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        "the call succeeded with account VDM disabled; the VDM metrics surface must be withdrawn"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
