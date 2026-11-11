"""presigned-mlflow-tracking-server-url-ttl."""
from __future__ import annotations

import http.cookiejar
import json
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from behavioral_harness import tags
from botocore.exceptions import ClientError


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "presigned-mlflow-tracking-server-url-ttl"
GROUP = "visibility-timeout-ttl"
SERVICES = ["sagemaker"]

_EXPIRES_IN_SECONDS = 5  # API_CreatePresignedMlflowTrackingServerUrl's documented minimum


# timing:real-time — ttl: 5 s https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_CreatePresignedMlflowTrackingServerUrl.html
@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """CreatePresignedMlflowTrackingServerUrl issues a URL that is usable immediately but no
    longer authorized once its ExpiresInSeconds window has elapsed.
    """
    s3 = ctx.client("s3")
    sm = ctx.client("sagemaker")
    tag_set = [{"Key": "sim2real-check", "Value": CHECK}]

    bucket_name = ctx.unique_name("sim2real-mlflow-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket_name))
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": tag_set})

    role_arn = _create_mlflow_role(ctx, tag_set)

    server_name = ctx.unique_name("sim2real-mlflow-ts-")
    _create_tracking_server_with_retry(sm, server_name, bucket_name, role_arn, tag_set)
    ctx.on_cleanup(lambda: _delete_tracking_server(sm, server_name))

    # CreateMlflowTrackingServer's own lifecycle terminates at "Created" — Starting/Started
    # belong to the separate Start/StopMlflowTrackingServer cost-control pair, which nothing
    # here calls, so waiting for "Started" would spin for the full timeout and never arrive.
    _poll_until(
        lambda: _tracking_server_status_reached(sm, server_name, "Created"),
        timeout_s=1800,
        interval_s=20,
    )

    fresh_url = sm.create_presigned_mlflow_tracking_server_url(
        TrackingServerName=server_name, ExpiresInSeconds=_EXPIRES_IN_SECONDS
    )["AuthorizedUrl"]
    fresh_authorized, fresh_status, fresh_final_url = _check_url(ctx, fresh_url)
    assert fresh_authorized, (
        "a brand-new presigned MLflow URL should be usable immediately "
        f"(status={fresh_status}, final_url={fresh_final_url!r})"
    )

    # A presigned URL is documented as single-use, so touching stale_url before its TTL has
    # elapsed would consume it while still valid and confound expiry with reuse rejection.
    # not_before_s holds off the first (and only, if AWS is deterministic) fetch attempt until
    # the TTL has definitely elapsed.
    stale_url = sm.create_presigned_mlflow_tracking_server_url(
        TrackingServerName=server_name, ExpiresInSeconds=_EXPIRES_IN_SECONDS
    )["AuthorizedUrl"]
    last_stale: dict = {}

    def _stale_still_authorized() -> bool:
        authorized, status, final_url = _check_url(ctx, stale_url)
        last_stale.update(status=status, final_url=final_url)
        return not authorized

    try:
        _poll_until(
            _stale_still_authorized,
            timeout_s=_EXPIRES_IN_SECONDS + 21,
            interval_s=3,
            not_before_s=_EXPIRES_IN_SECONDS + 1,
        )
    except AssertionError:
        raise AssertionError(
            "a presigned MLflow URL used after ExpiresInSeconds elapsed should not authorize "
            f"(status={last_stale.get('status')}, final_url={last_stale.get('final_url')!r})"
        ) from None


def _same_zone(final_url, presigned_url) -> bool:
    """Whether a redirect chain ended in the presigned URL's own zone: every host label after the
    first (service label, region, domain) is the presigned host's. A hand-off to a sign-in page
    on another host is not, and the domain is compared, never named."""
    final = (urlsplit(final_url or "").hostname or "").split(".")
    origin = (urlsplit(presigned_url).hostname or "").split(".")
    return len(origin) > 2 and all(origin) and final[1:] == origin[1:]


def _poll_until(predicate, *, timeout_s: float, interval_s: float, not_before_s: float = 0.0) -> None:
    start = time.monotonic()
    deadline = start + timeout_s
    while time.monotonic() < deadline:
        elapsed = time.monotonic() - start
        if elapsed < not_before_s:
            time.sleep(min(interval_s, not_before_s - elapsed))
            continue
        if predicate():
            return
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s")


def _tracking_server_status_reached(sm, server_name: str, want: str) -> bool:
    status = sm.describe_mlflow_tracking_server(TrackingServerName=server_name)["TrackingServerStatus"]
    if status in ("CreateFailed", "UpdateFailed"):
        raise AssertionError(f"tracking server entered {status} while waiting for {want}")
    return status == want


def _check_url(ctx, url: str) -> tuple[bool, int | None, str]:
    final_url, status = _fetch_final_url(ctx, url)
    if status is None or status >= 400:
        return False, status, final_url
    # An expired/unauthorized AuthorizedUrl can 200 into a sign-in page on another host instead
    # of erroring, so a bare status check alone would misclassify a rejected request as authorized.
    authorized = _same_zone(final_url, url)
    return authorized, status, final_url


def _fetch_final_url(ctx, url: str, timeout: float = 20.0):
    # The auth hop sets a session cookie before redirecting to the tracking server's own
    # domain, which needs that cookie to serve anything but a login bounce; a plain urlopen()
    # has no jar and drops it, so the final hop always looks unauthenticated.
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    req = _routed_request(ctx, url, headers={"User-Agent": "sim2real-behavioral-check/1.0"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.geturl(), resp.status
    except urllib.error.HTTPError as e:
        return getattr(e, "url", "") or "", e.code
    except Exception:
        return "", None


def _create_mlflow_role(ctx, tag_set) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-mlflow-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=tag_set
    )
    arn = resp["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonS3FullAccess")

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonS3FullAccess")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return arn


def _create_tracking_server_with_retry(sm, server_name, bucket_name, role_arn, tag_set) -> None:
    # A freshly-created IAM role can take a while to propagate; retry the bounded window that
    # SageMaker needs to be able to assume it, rather than assuming a fixed delay.
    deadline = time.monotonic() + 60
    while True:
        try:
            sm.create_mlflow_tracking_server(
                TrackingServerName=server_name,
                ArtifactStoreUri=f"s3://{bucket_name}/mlflow",
                RoleArn=role_arn,
                TrackingServerSize="Small",
                Tags=tag_set,
            )
            return
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _delete_tracking_server(sm, server_name: str) -> None:
    try:
        sm.delete_mlflow_tracking_server(TrackingServerName=server_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
