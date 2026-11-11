"""presigned-notebook-instance-url-session-duration-range-enforced."""
from __future__ import annotations

import http.cookiejar
import json
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from typing import Any

from botocore.config import Config
from behavioral_harness import tags
from botocore.exceptions import ClientError


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "presigned-notebook-instance-url-session-duration-range-enforced"
GROUP = "visibility-timeout-ttl"
SERVICES = ["sagemaker"]

#: CreatePresignedNotebookInstanceUrl SessionExpirationDurationInSeconds range.
_SESSION_MIN_S, _SESSION_MAX_S = 1800, 43200


def _refusal(fn):
    """The (code, message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call succeeded; expected a ClientError")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx: Any) -> None:
    """A presigned notebook instance URL authorizes when used at once, both with the default session
    duration and with the 1800 s minimum SessionExpirationDurationInSeconds; a session duration
    outside 1800-43200 s is refused with ValidationException and no URL.

    Reference: https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_CreatePresignedNotebookInstanceUrl.html
    """
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

    # Each URL is used once, immediately: it must land on an authenticated page in its own zone.
    for kwargs in ({}, {"SessionExpirationDurationInSeconds": _SESSION_MIN_S}):
        url = sm.create_presigned_notebook_instance_url(NotebookInstanceName=nb_name, **kwargs)["AuthorizedUrl"]
        try:
            authorized = _is_authenticated(ctx, url)
        except urllib.error.URLError as exc:
            raise AssertionError(f"no outbound network access to verify presigned URL redirect target: {exc}") from exc
        assert authorized, f"a freshly created presigned notebook instance URL ({kwargs or 'default session'}) should authenticate"

    # botocore enforces the model minimum locally; validation is off so it reaches SageMaker.
    raw_sm = ctx.client("sagemaker", config=Config(parameter_validation=False))
    for value, bound, limit in ((_SESSION_MIN_S - 1, "greater", _SESSION_MIN_S), (_SESSION_MAX_S + 1, "less", _SESSION_MAX_S)):
        got = _refusal(
            lambda v=value: raw_sm.create_presigned_notebook_instance_url(
                NotebookInstanceName=nb_name, SessionExpirationDurationInSeconds=v
            )
        )
        expected = (
            "ValidationException",
            f"1 validation error detected: Value '{value}' at 'sessionExpirationDurationInSeconds' "
            f"failed to satisfy constraint: Member must have value {bound} than or equal to {limit}",
        )
        assert got == expected, f"SessionExpirationDurationInSeconds={value}: expected {expected!r}, got {got!r}"


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
    ctx.on_cleanup(lambda: _absent_ok(lambda: iam.delete_role(RoleName=role_name)))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _absent_ok(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)))
    deadline = time.monotonic() + 60.0
    while True:
        try:
            iam.get_role(RoleName=role_name)
            return role["Arn"]
        except ClientError:
            if time.monotonic() >= deadline:
                raise AssertionError(f"role {role_name} did not become visible to IAM within 60s")
            time.sleep(2)


def _absent_ok(delete) -> None:
    """Run an IAM delete; an entity already gone is done."""
    try:
        delete()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _wait_notebook_status(ctx: Any, nb_name: str, want: str, timeout_s: float = 900.0, interval_s: float = 2.0) -> None:
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
