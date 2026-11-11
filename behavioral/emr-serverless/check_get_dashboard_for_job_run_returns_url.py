"""get-dashboard-for-job-run-returns-url."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-dashboard-for-job-run-returns-url"
GROUP = "read-operations"
SERVICES = ["emr-serverless"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:representation", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """GetDashboardForJobRun returns a usable, time-limited HTTPS dashboard URL for a real job run."""
    emrs = ctx.client("emr-serverless")
    role_arn = _create_execution_role(ctx)

    app_id = emrs.create_application(
        name=ctx.unique_name("sim2real-emrs-app-"),
        releaseLabel="emr-7.0.0",
        type="SPARK",
        clientToken=ctx.unique_name("tok-"),
        autoStartConfiguration={"enabled": True},
    )["applicationId"]
    ctx.on_cleanup(lambda: _stop_and_delete_application(emrs, app_id))
    _wait_for_application_state(ctx, app_id, {"CREATED"}, timeout_s=180.0)

    job_run_id = _start_job_run_with_role_retry(ctx, emrs, app_id, role_arn)
    ctx.on_cleanup(lambda: _cancel_job_run(emrs, app_id, job_run_id))

    # the dashboard cannot be served while the job run is still in SUBMITTED; wait until
    # it progresses to a state where the dashboard becomes available
    _wait_for_job_run_state(
        ctx, app_id, job_run_id, {"RUNNING", "SUCCESS", "FAILED", "CANCELLED"}, timeout_s=300.0
    )

    url = _wait_for_dashboard_url(ctx, app_id, job_run_id, timeout_s=120.0)
    assert isinstance(url, str) and url.startswith("https://"), (
        f"GetDashboardForJobRun returned a non-HTTPS or non-string url: {url!r}"
    )

    # the docstring's claim is "time-limited": a fresh call must mint an independently
    # signed link rather than echo a cached one back
    url_again = emrs.get_dashboard_for_job_run(applicationId=app_id, jobRunId=job_run_id)["url"]
    assert url_again != url, (
        f"GetDashboardForJobRun returned the identical url on a second call ({url!r}); "
        "a time-limited link must be freshly minted per call"
    )

    # and "usable": the link must actually resolve, not just look like a URL
    status = _fetch_status(ctx, url)
    assert status is not None and status < 500, (
        f"dashboard url {url!r} did not resolve (status={status!r})"
    )


def _wait_for_dashboard_url(ctx, app_id, job_run_id, timeout_s=120.0, interval_s=5.0):
    import time as _time
    from botocore.exceptions import ClientError
    emrs = ctx.client("emr-serverless")
    deadline = _time.monotonic() + timeout_s
    last_err = None
    while _time.monotonic() < deadline:
        try:
            return emrs.get_dashboard_for_job_run(applicationId=app_id, jobRunId=job_run_id)["url"]
        except ClientError as e:
            last_err = e
            _time.sleep(interval_s)
    raise AssertionError(f"dashboard never became available: {last_err}")


def _fetch_status(ctx, url, timeout_s=30.0):
    import urllib.error
    import urllib.request
    target, route = ctx.endpoint_route(url)
    try:
        with urllib.request.urlopen(
            urllib.request.Request(target, headers=route), timeout=timeout_s,
            context=_ssl_context(ctx.http_verify),
        ) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except urllib.error.URLError:
        return None


def _create_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-emrs-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "emr-serverless.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess")

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _start_job_run_with_role_retry(ctx, emrs, app_id, role_arn, timeout_s=90.0, interval_s=5.0):
    # a freshly created role is not immediately assumable by emr-serverless.amazonaws.com;
    # retry StartJobRun itself (bounded) instead of guessing a fixed propagation delay
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return emrs.start_job_run(
                applicationId=app_id,
                clientToken=ctx.unique_name("tok-"),
                executionRoleArn=role_arn,
                jobDriver={"sparkSubmit": {"entryPoint": "s3://sim2real-does-not-exist/none.py"}},
            )["jobRunId"]
        except ClientError as e:
            error = e.response.get("Error", {})
            code = error.get("Code", "")
            message = error.get("Message", "")
            if code in ("ValidationException", "AccessDeniedException") and "role" in message.lower():
                last_err = e
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"execution role {role_arn} never became assumable by emr-serverless: {last_err}")


def _wait_for_application_state(ctx, app_id, target_states, timeout_s=180.0, interval_s=5.0):
    emrs = ctx.client("emr-serverless")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = emrs.get_application(applicationId=app_id)["application"]["state"]
        if last in target_states:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"application never reached {target_states}, last state={last}")


_JOB_TERMINAL = {"SUCCESS", "FAILED", "CANCELLED"}


def _cancel_job_run(emrs, app_id, job_run_id, timeout_s=240.0, interval_s=5.0):
    """Cancel the job run and wait until it is terminal: StopApplication refuses while one runs."""
    from botocore.exceptions import ClientError

    try:
        emrs.cancel_job_run(applicationId=app_id, jobRunId=job_run_id)
    except ClientError:
        # Refused only for a run already terminal; the read below tells which.
        state = emrs.get_job_run(applicationId=app_id, jobRunId=job_run_id)["jobRun"]["state"]
        if state in _JOB_TERMINAL:
            return
        raise
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = emrs.get_job_run(applicationId=app_id, jobRunId=job_run_id)["jobRun"]["state"]
        if state in _JOB_TERMINAL:
            return
        time.sleep(interval_s)
    raise AssertionError(f"job run {job_run_id} still {state} {timeout_s}s after CancelJobRun")


def _stop_and_delete_application(emrs, app_id, timeout_s=300.0, interval_s=10.0):
    """Stop the application, retrying while it is still busy, then delete it once STOPPED."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        try:
            state = emrs.get_application(applicationId=app_id)["application"]["state"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        if state == "TERMINATED":
            return
        if state in ("CREATED", "STOPPED"):
            emrs.delete_application(applicationId=app_id)
            return
        if state == "STARTED":
            try:
                emrs.stop_application(applicationId=app_id)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "ValidationException":
                    raise
        time.sleep(interval_s)
    raise AssertionError(f"application {app_id} still {state} {timeout_s}s into its teardown")


def _wait_for_job_run_state(ctx, app_id, job_run_id, target_states, timeout_s=300.0, interval_s=5.0):
    emrs = ctx.client("emr-serverless")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = emrs.get_job_run(applicationId=app_id, jobRunId=job_run_id)["jobRun"]["state"]
        if last in target_states:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"job run never reached {target_states}, last state={last}")


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    import ssl

    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
