"""upload-job-state-transitions."""
from __future__ import annotations

import base64
import hashlib
import ssl
import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "upload-job-state-transitions"
GROUP = "state"
SERVICES = ["customer-profiles"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """UploadJobStatus: CREATED -> (StartUploadJob, after file upload) IN_PROGRESS -> (StopUploadJob) STOPPED."""
    cp = ctx.client("customer-profiles")
    domain = ctx.unique_name("sim2real-cp-dom-")

    cp.create_domain(DomainName=domain, DefaultExpirationDays=30, Tags={"sim2real": "behavioral"})
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: cp.delete_domain(DomainName=domain)))

    job_id = cp.create_upload_job(
        DomainName=domain,
        DisplayName="behavioral upload job",
        Fields={"email": {"Source": "email", "Target": "_profile.EmailAddress", "ContentType": "EMAIL_ADDRESS"}},
        UniqueKey="email",
    )["JobId"]

    created = cp.get_upload_job(DomainName=domain, JobId=job_id)
    assert created["Status"] == "CREATED", f"expected CREATED right after create_upload_job, got {created['Status']!r}"

    _upload_csv_for_job(ctx, cp, domain, job_id, "email\nbehavioral-upload@example.com\n")

    cp.start_upload_job(DomainName=domain, JobId=job_id)
    in_progress = _poll_until(
        lambda: cp.get_upload_job(DomainName=domain, JobId=job_id),
        lambda r: r["Status"] != "CREATED",
        timeout_s=60,
    )
    assert in_progress["Status"] == "IN_PROGRESS", (
        f"expected IN_PROGRESS after StartUploadJob, got {in_progress['Status']!r}"
    )

    cp.stop_upload_job(DomainName=domain, JobId=job_id)
    stopped = _poll_until(
        lambda: cp.get_upload_job(DomainName=domain, JobId=job_id),
        lambda r: r["Status"] != "IN_PROGRESS",
        timeout_s=60,
    )
    assert stopped["Status"] == "STOPPED", f"expected STOPPED after StopUploadJob, got {stopped['Status']!r}"


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
        assert resp.status in (200, 201, 204), f"presigned S3 PUT returned unexpected status {resp.status}"


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

