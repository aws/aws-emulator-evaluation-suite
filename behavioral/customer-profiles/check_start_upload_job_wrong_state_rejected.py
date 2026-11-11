"""start-upload-job-wrong-state-rejected."""
from __future__ import annotations

import base64
import hashlib
import ssl
import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-upload-job-wrong-state-rejected"
GROUP = "overly-permissive"
SERVICES = ["customer-profiles"]

#: The statuses of a started one-row upload job: running, or done.
_STARTED = {"IN_PROGRESS", "SUCCEEDED"}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """StartUploadJob on a job that has left CREATED (IN_PROGRESS, or SUCCEEDED once its one row is in) is
    rejected and leaves it started; a fresh job starts normally (positive control)."""
    cp = ctx.client("customer-profiles")
    domain = ctx.unique_name("sim2real-cp-dom-")
    fields = {"email": {"Source": "email", "Target": "_profile.EmailAddress", "ContentType": "EMAIL_ADDRESS"}}

    cp.create_domain(
        DomainName=domain,
        DefaultExpirationDays=30,
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: cp.delete_domain(DomainName=domain)))

    # positive control: starting a freshly created job succeeds.
    job1 = cp.create_upload_job(
        DomainName=domain, DisplayName="job1", Fields=fields, UniqueKey="email"
    )["JobId"]
    _upload_csv_for_job(ctx, cp, domain, job1, "email\nbehavioral-upload-1@example.com\n")
    cp.start_upload_job(DomainName=domain, JobId=job1)
    # A started one-row job is IN_PROGRESS and may already be SUCCEEDED by the first read.
    started1 = _poll_until(
        lambda: cp.get_upload_job(DomainName=domain, JobId=job1),
        lambda r: r["Status"] != "CREATED",
        timeout_s=60,
    )
    assert started1["Status"] in _STARTED, (
        f"expected job1 IN_PROGRESS or SUCCEEDED after start, got {started1['Status']!r}"
    )

    # break: a job that has left CREATED cannot be started again.
    code, message = _error(lambda: cp.start_upload_job(DomainName=domain, JobId=job1))
    assert code == "BadRequestException", (
        f"expected BadRequestException re-starting a started job, got {code!r}"
    )
    assert message == "Job status is not in CREATED status and cannot be started", (
        f"unexpected message re-starting a started job: {message!r}"
    )

    # effect absent: the rejected re-start did not reset or fail job1.
    after_restart = cp.get_upload_job(DomainName=domain, JobId=job1)
    assert after_restart["Status"] in _STARTED, (
        f"expected job1 still IN_PROGRESS or SUCCEEDED after rejected re-start, "
        f"got {after_restart['Status']!r}"
    )

    # no restore leg: an already-started job can never be started again (always-invalid,
    # not broken-then-restored) — a second positive control on a distinct job demonstrates
    # StartUploadJob itself still works.
    job2 = cp.create_upload_job(
        DomainName=domain, DisplayName="job2", Fields=fields, UniqueKey="email"
    )["JobId"]
    _upload_csv_for_job(ctx, cp, domain, job2, "email\nbehavioral-upload-2@example.com\n")
    cp.start_upload_job(DomainName=domain, JobId=job2)
    started = _poll_until(
        lambda: cp.get_upload_job(DomainName=domain, JobId=job2),
        lambda r: r["Status"] != "CREATED",
        timeout_s=60,
    )
    assert started["Status"] in _STARTED, (
        f"expected job2 IN_PROGRESS or SUCCEEDED after start, got {started['Status']!r}"
    )


def _upload_csv_for_job(ctx, cp, domain, job_id, csv_body: str) -> None:
    path = cp.get_upload_job_path(DomainName=domain, JobId=job_id)
    key_bytes = base64.b64decode(path["ClientToken"])
    key_md5 = base64.b64encode(hashlib.md5(key_bytes).digest()).decode()
    # The upload URL is presigned, so its signature covers the host: send the route headers.
    url, route_headers = ctx.endpoint_route(path["Url"])
    req = urllib.request.Request(
        url,
        data=csv_body.encode("utf-8"),
        method="PUT",
        headers={
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": path["ClientToken"],
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
            **route_headers,
        },
    )
    with urllib.request.urlopen(req, timeout=30, context=_ssl_context(ctx.http_verify)) as resp:
        assert resp.status in (200, 201, 204), (
            f"expected 200/201/204 uploading job CSV, got {resp.status}"
        )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

