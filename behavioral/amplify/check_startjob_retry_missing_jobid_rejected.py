"""startjob-retry-missing-jobid-rejected."""
from __future__ import annotations

import io
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "startjob-retry-missing-jobid-rejected"
GROUP = "overly-permissive"
SERVICES = ["amplify"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """StartJob(jobType=RETRY) without a jobId on an app with no repository is rejected and creates
    no job history; AWS refuses it because the app is not repository-connected."""
    amplify = ctx.client("amplify")
    app_id = _create_app(ctx)

    branch_name = ctx.unique_name("branch-")
    amplify.create_branch(appId=app_id, branchName=branch_name)
    ctx.on_cleanup(lambda: _ignore(lambda: amplify.delete_branch(appId=app_id, branchName=branch_name)))

    err = _client_error(
        lambda: amplify.start_job(appId=app_id, branchName=branch_name, jobType="RETRY")
    )
    assert err == (
        "BadRequestException",
        "Operation not supported for app that was not connected to a repository provider. "
        "Please use CreateDeployment and StartDeployment operations instead.",
    ), err

    jobs_after_failure = amplify.list_jobs(appId=app_id, branchName=branch_name)["jobSummaries"]
    assert jobs_after_failure == [], jobs_after_failure

    # Positive control: a correctly-formed manual deployment on the same branch is accepted.
    deployment = amplify.create_deployment(appId=app_id, branchName=branch_name)
    job_id = deployment["jobId"]
    _http_put(ctx, deployment["zipUploadUrl"], _build_site_zip())
    started = amplify.start_deployment(appId=app_id, branchName=branch_name, jobId=job_id)
    assert started["jobSummary"]["jobId"] == job_id, started

    # Independent read at the destination: the accepted job is visible through GetJob, not just
    # echoed back by the call that created it.
    visible = amplify.get_job(appId=app_id, branchName=branch_name, jobId=job_id)["job"]
    assert visible["summary"]["jobId"] == job_id, visible
    assert visible["summary"]["status"] in (
        "PENDING",
        "PROVISIONING",
        "RUNNING",
        "CREATED",
        "SUCCEED",
    ), visible["summary"]["status"]

    ctx.on_cleanup(
        lambda: _ignore(lambda: amplify.delete_job(appId=app_id, branchName=branch_name, jobId=job_id))
    )
    ctx.on_cleanup(
        lambda: _ignore(lambda: amplify.stop_job(appId=app_id, branchName=branch_name, jobId=job_id))
    )


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
    import urllib.request

    target_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(target_url, data=data, method="PUT", headers=route_headers)
    with urllib.request.urlopen(req, timeout=60) as resp:
        assert resp.status in (200, 204)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
