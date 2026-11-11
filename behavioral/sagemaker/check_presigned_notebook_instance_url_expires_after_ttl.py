"""presigned-notebook-instance-url-expires-after-ttl."""
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


CHECK = "presigned-notebook-instance-url-expires-after-ttl"
GROUP = "visibility-timeout-ttl"
SERVICES = ["sagemaker"]


# timing:real-time — ttl: 300 s https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_CreatePresignedNotebookInstanceUrl.html
@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data", "timing:real-time")
def run(ctx: Any) -> None:
    """A presigned notebook instance URL is only usable within its fixed 5-minute
    window (CreatePresignedNotebookInstanceUrl is not configurable down from that) and
    is rejected/redirected to sign-in after expiry."""
    sm = ctx.client("sagemaker")
    role_arn = _create_sagemaker_role(ctx)

    nb_name = ctx.unique_name("sim2real-nb-")
    sm.create_notebook_instance(
        NotebookInstanceName=nb_name,
        InstanceType="ml.t3.medium",
        RoleArn=role_arn,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _cleanup_notebook_instance(ctx, nb_name))
    _wait_notebook_status(ctx, nb_name, "InService")

    # Fresh URL, used immediately: must land on an authenticated redirect in its own zone.
    fresh_url = sm.create_presigned_notebook_instance_url(NotebookInstanceName=nb_name)["AuthorizedUrl"]
    try:
        fresh_ok = _is_authenticated(ctx, fresh_url)
    except urllib.error.URLError as exc:
        raise AssertionError(f"no outbound network access to verify presigned URL redirect target: {exc}") from exc
    assert fresh_ok, "a freshly created presigned notebook instance URL should redirect to an authenticated session"

    # A second URL, deliberately left COMPLETELY UNTOUCHED past the documented fixed
    # 5-minute validity window (API_CreatePresignedNotebookInstanceUrl.html: "valid
    # only for 5 minutes ... If you try to use the URL after the 5-minute limit
    # expires, you are directed to the AWS console sign-in page"). Confirmed against
    # real AWS: probing this URL even once during the wait counts as "using" it, which
    # opens a Jupyter session that then stays authenticated for
    # SessionExpirationDurationInSeconds (same API, default 12 hours) independently of
    # the URL's own 5-minute window -- polling the URL
    # during the wait keeps a session authenticated for over 1200s
    # on real AWS. So the wait below never touches the URL, and it is checked exactly
    # once, after the deadline.
    stale_url = sm.create_presigned_notebook_instance_url(NotebookInstanceName=nb_name)["AuthorizedUrl"]
    deadline = time.monotonic() + 330.0  # 5 min documented TTL + 30s margin
    while time.monotonic() < deadline:
        time.sleep(min(15.0, deadline - time.monotonic()))
    stale_ok = _is_authenticated(ctx, stale_url)
    assert not stale_ok, "a presigned notebook instance URL used after its 5-minute window should no longer authenticate"

    # The URL's expiry is a property of the URL, not of the underlying instance.
    described = sm.describe_notebook_instance(NotebookInstanceName=nb_name)
    assert described["NotebookInstanceStatus"] == "InService", (
        "notebook instance should remain InService independent of the presigned URL's expiry, got "
        f"{described['NotebookInstanceStatus']}"
    )


def _same_zone(final_url, presigned_url) -> bool:
    """Whether a redirect chain ended in the presigned URL's own zone: every host label after the
    first (service label, region, domain) is the presigned host's. A hand-off to a sign-in page
    on another host is not, and the domain is compared, never named."""
    final = (urlsplit(final_url or "").hostname or "").split(".")
    origin = (urlsplit(presigned_url).hostname or "").split(".")
    return len(origin) > 2 and all(origin) and final[1:] == origin[1:]


def _is_authenticated(ctx, url: str, timeout: float = 15.0) -> bool:
    # The auth hop sets a session cookie and redirects to the notebook host, which needs it back;
    # without a cookie jar the notebook host bounces the request to the console instead.
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    req = _routed_request(ctx, url, headers={"User-Agent": "sim2real-behavioral-check/1.0"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            final_url, status = resp.geturl(), resp.status
    except urllib.error.HTTPError as exc:
        final_url, status = exc.geturl(), exc.code
    return status < 400 and _same_zone(final_url, url)


def _create_sagemaker_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    deadline = time.monotonic() + 60.0
    while True:
        try:
            iam.get_role(RoleName=role_name)
            return role["Arn"]
        except ClientError:
            if time.monotonic() >= deadline:
                raise AssertionError(f"role {role_name} did not become visible to IAM within 60s")
            time.sleep(2)


def _wait_notebook_status(ctx: Any, nb_name: str, want: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> None:
    sm = ctx.client("sagemaker")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = sm.describe_notebook_instance(NotebookInstanceName=nb_name)["NotebookInstanceStatus"]
        if status == want:
            return
        if status == "Failed":
            raise AssertionError(f"notebook instance entered Failed while waiting for {want}")
        time.sleep(interval_s)
    raise AssertionError(f"notebook instance did not reach {want} within {timeout_s}s")


def _cleanup_notebook_instance(ctx: Any, nb_name: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        status = sm.describe_notebook_instance(NotebookInstanceName=nb_name)["NotebookInstanceStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ValidationException":
            return
        raise
    # StopNotebookInstance is accepted only InService, so wait out Pending/Updating first.
    deadline = time.monotonic() + 600
    stop_requested = False
    while status not in ("Stopped", "Failed", "Deleting"):
        if status == "InService" and not stop_requested:
            sm.stop_notebook_instance(NotebookInstanceName=nb_name)
            stop_requested = True
        if time.monotonic() >= deadline:
            raise AssertionError(f"notebook instance {nb_name} still {status} after 600s of teardown")
        time.sleep(2)
        status = sm.describe_notebook_instance(NotebookInstanceName=nb_name)["NotebookInstanceStatus"]
    if status != "Deleting":
        sm.delete_notebook_instance(NotebookInstanceName=nb_name)
    deadline = time.monotonic() + 300
    while True:
        try:
            sm.describe_notebook_instance(NotebookInstanceName=nb_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"notebook instance {nb_name} still present 300s after its delete")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
