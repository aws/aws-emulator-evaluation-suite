"""export-job-lifecycle."""
from __future__ import annotations
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "export-job-lifecycle"
GROUP = 'export-job'
SERVICES = ['sesv2']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ses-account")
def run(ctx) -> None:
    """A metrics export job is listed and polls to a terminal JobStatus; CancelExportJob cancels a
    fresh job (CANCELLED in GetExportJob and ListExportJobs) but is rejected with BadRequestException
    and the exact status message once the job is terminal, leaving its status unchanged."""
    ses = ctx.client('sesv2')
    from datetime import datetime, timedelta, timezone
    # Metrics export requires VDM; it is enabled for the run and restored afterwards.
    original_vdm = ses.get_account().get('VdmAttributes', {}).get('VdmEnabled')
    if original_vdm != 'ENABLED':
        ses.put_account_vdm_attributes(VdmAttributes={'VdmEnabled': 'ENABLED'})
        ctx.on_cleanup(
            lambda: ses.put_account_vdm_attributes(VdmAttributes={'VdmEnabled': original_vdm or 'DISABLED'})
        )
        _deadline = time.monotonic() + _budget_s(ctx, 60)
        _poll = None
        while time.monotonic() < _deadline:
            _poll = ses.get_account()
            if _poll.get('VdmAttributes', {}).get('VdmEnabled') == 'ENABLED':
                break
            time.sleep(1)
        else:
            if _budget_spent(ctx):
                raise TimeoutError("VdmEnabled reading ENABLED: the run budget ended first; not graded")
            raise AssertionError('condition not met within ' + str(60) + 's. Last result: ' + repr(_poll))
    end = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    start = end - timedelta(days=2)
    _src = {'MetricsDataSource': {'Dimensions': {'ISP': ['*']}, 'Namespace': 'VDM', 'Metrics': [{'Name': 'SEND', 'Aggregation': 'VOLUME'}], 'StartDate': start, 'EndDate': end}}
    _dst = {'DataFormat': 'CSV'}

    # Positive control: cancelling a fresh job works, so the later rejection is about the
    # job being terminal, not CancelExportJob always failing.
    # A job that reaches a terminal status before the cancel lands proves nothing either way,
    # so the control retries with a fresh job.
    control_errors = []
    for _ in range(5):
        control_id = ses.create_export_job(ExportDataSource=_src, ExportDestination=_dst)['JobId']
        try:
            ses.cancel_export_job(JobId=control_id)
            break
        except ClientError as exc:
            status = ses.get_export_job(JobId=control_id).get('JobStatus')
            if exc.response.get('Error', {}).get('Code') != 'BadRequestException' or status not in ('COMPLETED', 'FAILED'):
                raise
            control_errors.append((status, exc.response.get('Error')))
    else:
        raise AssertionError(f'positive control: every fresh job was terminal before CancelExportJob landed: {control_errors!r}')
    control_after = ses.get_export_job(JobId=control_id)
    assert control_after['JobStatus'] == 'CANCELLED', f'positive control: expected CANCELLED, got {control_after["JobStatus"]}'
    control_listed = {j['JobId']: j['JobStatus'] for j in ses.list_export_jobs().get('ExportJobs', [])}
    assert control_listed.get(control_id) == 'CANCELLED', f'ListExportJobs disagrees with GetExportJob on cancelled control job: {control_listed.get(control_id)}'

    resp = ses.create_export_job(ExportDataSource=_src, ExportDestination=_dst)
    job_id = resp['JobId']
    got = ses.get_export_job(JobId=job_id)
    assert got['JobId'] == job_id, got['JobId']
    assert got['ExportSourceType'] == 'METRICS_DATA', got.get('ExportSourceType')
    assert got['JobStatus'] in ('CREATED', 'PROCESSING', 'COMPLETED', 'FAILED', 'CANCELLED'), got['JobStatus']
    listed = ses.list_export_jobs()
    assert job_id in [j['JobId'] for j in listed.get('ExportJobs', [])], 'created job missing from ListExportJobs'
    _deadline = time.monotonic() + _budget_s(ctx, 300)
    final = None
    while time.monotonic() < _deadline:
        final = ses.get_export_job(JobId=job_id)
        if final.get('JobStatus') in ('COMPLETED', 'FAILED', 'CANCELLED'):
            break
        time.sleep(1)
    else:
        if _budget_spent(ctx):
            raise TimeoutError("export job reaching a terminal JobStatus: the run budget ended first; not graded")
        raise AssertionError('condition not met within ' + str(300) + 's. Last result: ' + repr(final))
    assert final['JobStatus'] in ('COMPLETED', 'FAILED', 'CANCELLED'), final['JobStatus']
    err = _error(lambda: ses.cancel_export_job(JobId=job_id))
    assert err.get('Code') == 'BadRequestException', f'expected BadRequestException, got {err!r}'
    expected = f"Cannot cancel an export job that has a <{final['JobStatus']}> status."
    assert err.get('Message') == expected, f"expected message {expected!r}, got {err.get('Message')!r}"
    after = ses.get_export_job(JobId=job_id)
    assert after['JobStatus'] == final['JobStatus'], f'rejected cancel changed status: {final["JobStatus"]} -> {after["JobStatus"]}'


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _error(fn):
    """Call fn() and return its botocore Error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
