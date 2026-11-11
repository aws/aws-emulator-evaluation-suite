"""presigned-mlflow-tracking-server-url-expires-after-ttl."""
from __future__ import annotations

import http.cookiejar
import json
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "presigned-mlflow-tracking-server-url-expires-after-ttl"
GROUP = "visibility-timeout-ttl"
SERVICES = ["sagemaker"]


# timing:real-time — ttl: 5 s https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_CreatePresignedMlflowTrackingServerUrl.html
@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data", "timing:real-time")
def run(ctx: Any) -> None:
    """A presigned MLflow tracking server URL created with the minimum
    ExpiresInSeconds window (5s) no longer authenticates once that window has
    elapsed, denying access on stale links rather than honoring them indefinitely."""
    sm = ctx.client("sagemaker")
    s3 = ctx.client("s3")
    role_arn = _create_sagemaker_role(ctx)

    bucket = ctx.unique_name("sim2real-mlflow-").lower().replace("_", "-")
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    ts_name = ctx.unique_name("sim2real-mlflow-ts-")
    sm.create_mlflow_tracking_server(
        TrackingServerName=ts_name,
        ArtifactStoreUri=f"s3://{bucket}/artifacts",
        RoleArn=role_arn,
    )
    ctx.on_cleanup(lambda: _cleanup_tracking_server(ctx, ts_name))
    _wait_tracking_server_status(ctx, ts_name, "Created")

    # Fresh URL, used immediately: must land on an authenticated redirect in its own zone.
    # A tracking server reporting Created+Active can still take a short while before the
    # MLflow UI behind it actually serves requests, so this mints a NEW presigned URL on
    # each attempt (never reusing one — AuthorizedUrl is documented single-use) and retries
    # on that real gap rather than trusting the describe-side status alone.
    def _fresh_attempt() -> tuple[bool, str, int]:
        url = sm.create_presigned_mlflow_tracking_server_url(
            TrackingServerName=ts_name, ExpiresInSeconds=300
        )["AuthorizedUrl"]
        try:
            return _probe(ctx, url)
        except urllib.error.URLError as exc:
            raise AssertionError(f"no outbound network access to verify presigned URL redirect target: {exc}") from exc

    fresh_ok, last_final_url, last_status = False, "", 0
    deadline = time.monotonic() + 180.0
    while time.monotonic() < deadline:
        fresh_ok, last_final_url, last_status = _fresh_attempt()
        if fresh_ok:
            break
        time.sleep(15.0)
    assert fresh_ok, (
        "a freshly created presigned MLflow tracking server URL should authenticate within 180s "
        f"of the tracking server reaching Created+Active; last observed status={last_status} "
        f"final_url={last_final_url!r}"
    )

    # A second URL, created with the minimum ExpiresInSeconds (5s per
    # API_CreatePresignedMlflowTrackingServerUrl.html), left unused until after the
    # window elapses, then used exactly once - the URL is documented as single-use, so
    # this avoids conflating expiry with single-use consumption on the same URL.
    stale_url = sm.create_presigned_mlflow_tracking_server_url(
        TrackingServerName=ts_name, ExpiresInSeconds=5
    )["AuthorizedUrl"]
    time.sleep(20)  # 4x the 5s TTL, documented minimum window
    stale_ok, stale_final_url, stale_status = _probe(ctx, stale_url)
    assert not stale_ok, (
        "a presigned MLflow tracking server URL used after ExpiresInSeconds elapsed should not "
        f"authenticate; observed status={stale_status} final_url={stale_final_url!r}"
    )


def _same_zone(final_url, presigned_url) -> bool:
    """Whether a redirect chain ended in the presigned URL's own zone: every host label after the
    first (service label, region, domain) is the presigned host's. A hand-off to a sign-in page
    on another host is not, and the domain is compared, never named."""
    final = (urlsplit(final_url or "").hostname or "").split(".")
    origin = (urlsplit(presigned_url).hostname or "").split(".")
    return len(origin) > 2 and all(origin) and final[1:] == origin[1:]


def _probe(ctx, url: str, timeout: float = 15.0) -> tuple[bool, str, int]:
    # The auth hop sets a session cookie before redirecting to the tracking server's own
    # domain; a bare urlopen() carries no cookie jar across that redirect and the final GET
    # arrives with no session, reading as unauthenticated even for a genuinely valid link.
    # A fresh jar per call mirrors a browser starting cold from the presigned link.
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    req = _routed_request(ctx, url, headers={"User-Agent": "sim2real-behavioral-check/1.0"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            final_url, status = resp.geturl(), resp.status
    except urllib.error.HTTPError as exc:
        final_url, status = exc.geturl(), exc.code
    ok = status < 400 and _same_zone(final_url, url)
    return ok, final_url, status


def _create_sagemaker_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    for _ in range(15):
        try:
            iam.get_role(RoleName=role_name)
            break
        except ClientError:
            time.sleep(2)
    time.sleep(10)  # IAM trust-policy propagation lag; get_role succeeding does not mean sagemaker.amazonaws.com can assume it yet
    return role["Arn"]


def _wait_tracking_server_status(ctx: Any, ts_name: str, want: str, timeout_s: float = 1800.0, interval_s: float = 20.0) -> None:
    sm = ctx.client("sagemaker")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = sm.describe_mlflow_tracking_server(TrackingServerName=ts_name)
        status = desc["TrackingServerStatus"]
        if status == want and desc.get("IsActive") == "Active":
            return
        if status in ("CreateFailed", "UpdateFailed"):
            raise AssertionError(f"tracking server entered {status} while waiting for {want}")
        time.sleep(interval_s)
    raise AssertionError(f"tracking server did not reach {want}+Active within {timeout_s}s")


def _cleanup_tracking_server(ctx: Any, ts_name: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        sm.delete_mlflow_tracking_server(TrackingServerName=ts_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise
    # A deletion can outlast the teardown budget, so a server still Deleting at the deadline is
    # left to finish; a failed deletion raises.
    deadline = time.monotonic() + 600
    status = None
    while time.monotonic() < deadline:
        try:
            status = sm.describe_mlflow_tracking_server(TrackingServerName=ts_name)["TrackingServerStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFound":
                return
            raise
        if status == "DeleteFailed":
            raise AssertionError(f"tracking server {ts_name} failed to delete")
        time.sleep(15)
    if status != "Deleting":
        raise AssertionError(f"tracking server {ts_name} is {status!r}, not Deleting, after 600s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
