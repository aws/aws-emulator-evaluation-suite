"""manual-deploy-build-and-serve-roundtrip."""
from __future__ import annotations

import base64
import io
import secrets
import time
import urllib.error
import urllib.request
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "manual-deploy-build-and-serve-roundtrip"
GROUP = "data-plane"
SERVICES = ["amplify"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A zip uploaded to CreateDeployment's presigned URL and started with StartDeployment yields a
    SUCCEED job with recorded steps, and the branch's basic-auth-protected default domain serves the
    zip's content over HTTPS."""
    amplify = ctx.client("amplify")
    name = ctx.unique_name("sim2real-amplify-app-")
    app = amplify.create_app(name=name, platform="WEB", tags={"sim2real-check": CHECK})["app"]
    app_id = app["appId"]
    ctx.on_cleanup(lambda: _ignore(lambda: amplify.delete_app(appId=app_id)))

    branch_name = ctx.unique_name("main")
    # Basic auth with a per-run secret keeps the hosted branch closed to anyone but this check.
    basic = base64.b64encode(f"sim2real:{secrets.token_urlsafe(24)}".encode()).decode()
    amplify.create_branch(
        appId=app_id, branchName=branch_name, stage="PRODUCTION", tags={"sim2real-check": CHECK},
        enableBasicAuth=True, basicAuthCredentials=basic,
    )
    ctx.on_cleanup(lambda: _ignore(lambda: amplify.delete_branch(appId=app_id, branchName=branch_name)))

    marker = ctx.unique_name("sim2real-marker-")
    zip_bytes = _build_site_zip(marker)

    deployment = amplify.create_deployment(appId=app_id, branchName=branch_name)
    job_id = deployment["jobId"]
    zip_upload_url = deployment["zipUploadUrl"]

    _http_put(ctx, zip_upload_url, zip_bytes)

    amplify.start_deployment(appId=app_id, branchName=branch_name, jobId=job_id)

    status = _poll_job_status(ctx, app_id, branch_name, job_id, timeout_s=420)
    assert status == "SUCCEED", f"deployment job ended in {status!r}, not SUCCEED"

    job = amplify.get_job(appId=app_id, branchName=branch_name, jobId=job_id)["job"]
    assert len(job["steps"]) > 0, "expected the completed job to record build/deploy steps"

    fetched_app = amplify.get_app(appId=app_id)["app"]
    site_url = f"https://{branch_name}.{fetched_app['defaultDomain']}/"
    body = _poll_http_get(ctx, site_url, expected_substring=marker, timeout_s=180, basic=basic)
    assert marker in body, f"deployed content did not contain marker {marker!r}"


def _ignore(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _build_site_zip(marker: str) -> bytes:
    buf = io.BytesIO()
    html = f"<html><body>{marker}</body></html>"
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.html", html)
    return buf.getvalue()


def _http_put(ctx, url: str, data: bytes) -> None:
    target_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(target_url, data=data, method="PUT", headers=route_headers)
    with urllib.request.urlopen(req, timeout=60) as resp:
        assert resp.status in (200, 204), f"presigned PUT failed with status {resp.status}"


def _poll_job_status(ctx, app_id: str, branch_name: str, job_id: str, timeout_s: float) -> str:
    amplify = ctx.client("amplify")
    terminal = {"SUCCEED", "FAILED", "CANCELLED"}
    deadline = time.monotonic() + _capped(ctx, timeout_s)
    status = "CREATED"
    while time.monotonic() < deadline:
        job = amplify.get_job(appId=app_id, branchName=branch_name, jobId=job_id)["job"]
        status = job["summary"]["status"]
        if status in terminal:
            return status
        time.sleep(2)
    return status


def _poll_http_get(ctx, url: str, expected_substring: str, timeout_s: float, basic: str) -> str:
    deadline = time.monotonic() + _capped(ctx, timeout_s)
    last_body = ""
    while time.monotonic() < deadline:
        try:
            target_url, route_headers = ctx.endpoint_route(url)
            headers = {**route_headers, "Authorization": f"Basic {basic}"}
            with urllib.request.urlopen(urllib.request.Request(target_url, headers=headers), timeout=20) as resp:
                last_body = resp.read().decode("utf-8", errors="replace")
            if expected_substring in last_body:
                return last_body
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            pass
        time.sleep(2)
    return last_body


def _capped(ctx, seconds: float) -> float:
    """A poll timeout of `seconds`, bounded by the runner's remaining time when it has a budget."""
    left = ctx.time_left()
    return seconds if left is None else min(seconds, left)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
