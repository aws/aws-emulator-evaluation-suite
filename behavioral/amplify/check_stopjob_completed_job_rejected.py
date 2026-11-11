"""stopjob-completed-job-rejected."""
from __future__ import annotations

import io
import time
import urllib.request
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "stopjob-completed-job-rejected"
GROUP = "overly-permissive"
SERVICES = ["amplify"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """StopJob succeeds on an in-flight job but is rejected once that same job reaches a terminal
    state; a job that finished before the first stop refuses both stops."""
    amplify = ctx.client("amplify")
    app_id = _create_app(ctx)

    branch_name = ctx.unique_name("branch-")
    amplify.create_branch(appId=app_id, branchName=branch_name)
    ctx.on_cleanup(lambda: _ignore(lambda: amplify.delete_branch(appId=app_id, branchName=branch_name)))

    deployment = amplify.create_deployment(appId=app_id, branchName=branch_name)
    job_id = deployment["jobId"]
    _http_put(ctx, deployment["zipUploadUrl"], _build_site_zip())
    amplify.start_deployment(appId=app_id, branchName=branch_name, jobId=job_id)

    refused = (
        "BadRequestException",
        "Unable to cancel job. The given job is already in a terminal state.",
    )
    try:
        stop_resp = amplify.stop_job(appId=app_id, branchName=branch_name, jobId=job_id)
    except ClientError as exc:
        # The deployment finished before the stop arrived: the first stop is the terminal-state
        # refusal itself, and the job keeps the status it finished with.
        err = (exc.response["Error"].get("Code", ""), exc.response["Error"].get("Message", ""))
        assert err == refused, err
        terminal_status = _poll_until_terminal(ctx, app_id, branch_name, job_id, timeout_s=180)
        assert terminal_status == "SUCCEED", f"expected SUCCEED, got {terminal_status!r}"
    else:
        # Positive control: stopping a job that is still in flight is accepted.
        stopping_status = stop_resp["jobSummary"]["status"]
        assert stopping_status in ("CANCELLING", "CANCELLED"), (
            f"expected CANCELLING or CANCELLED, got {stopping_status!r}"
        )
        terminal_status = _poll_until_terminal(ctx, app_id, branch_name, job_id, timeout_s=180)
        assert terminal_status == "CANCELLED", f"expected CANCELLED, got {terminal_status!r}"

    # Break exactly one thing: stop the same job again now that it is already terminal.
    err = _client_error(lambda: amplify.stop_job(appId=app_id, branchName=branch_name, jobId=job_id))
    assert err == refused, err

    # Effect absent: the job's terminal status did not change/revert because of the rejected call.
    unchanged = amplify.get_job(appId=app_id, branchName=branch_name, jobId=job_id)["job"]
    unchanged_status = unchanged["summary"]["status"]
    assert unchanged_status == terminal_status, f"expected {terminal_status}, got {unchanged_status!r}"

    amplify.delete_job(appId=app_id, branchName=branch_name, jobId=job_id)
    remaining = amplify.list_jobs(appId=app_id, branchName=branch_name)["jobSummaries"]
    assert all(j["jobId"] != job_id for j in remaining), (
        f"deleted job {job_id} still present in list_jobs: {remaining}"
    )

    err_deleted = _client_error(lambda: amplify.get_job(appId=app_id, branchName=branch_name, jobId=job_id))
    assert err_deleted == ("NotFoundException", f"Job {job_id} not found."), err_deleted


def _ignore(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _client_error(fn) -> tuple[str, str]:
    """Call fn() and return its (code, message); an unexpected success raises, so an emulator
    accepting a call real AWS refuses never reads as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected a ClientError, call succeeded: {result!r}")


def _create_app(ctx) -> str:
    amplify = ctx.client("amplify")
    name = ctx.unique_name("sim2real-amplify-app-")
    app = amplify.create_app(name=name, tags={"sim2real-check": CHECK})["app"]
    ctx.on_cleanup(lambda: _ignore(lambda: amplify.delete_app(appId=app["appId"])))
    return app["appId"]


def _build_site_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.html", "<html><body>hi</body></html>")
    return buf.getvalue()


def _http_put(ctx, url: str, data: bytes) -> None:
    target_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(target_url, data=data, method="PUT", headers=route_headers)
    with urllib.request.urlopen(req, timeout=60) as resp:
        assert resp.status in (200, 204), f"expected 200/204, got {resp.status}"


def _poll_until_terminal(ctx, app_id: str, branch_name: str, job_id: str, timeout_s: float) -> str:
    amplify = ctx.client("amplify")
    terminal = {"SUCCEED", "FAILED", "CANCELLED"}
    deadline = time.monotonic() + timeout_s
    status = "CANCELLING"
    while time.monotonic() < deadline:
        job = amplify.get_job(appId=app_id, branchName=branch_name, jobId=job_id)["job"]
        status = job["summary"]["status"]
        if status in terminal:
            return status
        time.sleep(5)
    raise AssertionError(
        f"job {job_id} did not reach a terminal state within {timeout_s}s; last saw {status!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
