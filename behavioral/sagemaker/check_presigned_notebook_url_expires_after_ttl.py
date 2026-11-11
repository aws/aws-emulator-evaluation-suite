"""presigned-notebook-url-expires-after-ttl."""
from __future__ import annotations

import http.cookiejar
import json
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "presigned-notebook-url-expires-after-ttl"
GROUP = "visibility-timeout-ttl"
SERVICES = ["sagemaker"]

# Per AWS docs (API_CreatePresignedNotebookInstanceUrl.html note): "The URL that you get from a
# call to CreatePresignedNotebookInstanceUrl is valid only for 5 minutes." This window is fixed
# and is NOT controlled by the SessionExpirationDurationInSeconds request parameter (that field
# only bounds the *authenticated Jupyter session* length after the URL is used, 1800-43200s).
_URL_TTL_SECONDS = 300
# Checkpoint comfortably before the TTL boundary, to prove the URL has NOT expired early.
_MID_WINDOW_CHECKPOINT_S = 240.0


# timing:real-time — ttl: 300 s https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_CreatePresignedNotebookInstanceUrl.html
@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A CreatePresignedNotebookInstanceUrl URL opens the Jupyter server (HTTP 200, same host) when used at once and is
    still accepted mid-window, but redirects away once its 5-minute TTL has elapsed, while the notebook stays InService.
    """
    # A real notebook instance bills by the minute and takes several minutes to reach
    # InService; on top of that this check must wait out the documented, non-configurable
    # 5-minute presigned-URL TTL. It pays that on every backend, on a small instance
    # type (ml.t3.medium; ml.t2 is deprecated for notebook instances) and stopping plus
    # deleting the notebook on cleanup -- an expiry nobody waits for is an expiry nobody
    # has evidence of.
    iam = ctx.client("iam")
    sm = ctx.client("sagemaker")

    role_arn = _create_sagemaker_execution_role(ctx, iam)
    notebook_name = ctx.unique_name("sim2real-behav-nb-")
    sm.create_notebook_instance(
        NotebookInstanceName=notebook_name,
        InstanceType="ml.t3.medium",
        RoleArn=role_arn,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_notebook_instance_and_wait(sm, notebook_name))
    _poll_until(
        lambda: sm.describe_notebook_instance(NotebookInstanceName=notebook_name),
        lambda d: d["NotebookInstanceStatus"] == "InService",
        timeout_s=900.0,
        interval_s=15.0,
    )

    presigned = sm.create_presigned_notebook_instance_url(NotebookInstanceName=notebook_name)
    url = presigned["AuthorizedUrl"]
    assert not (p := ctx.published_url_mismatch(url, labels=("notebook", ctx.region, "sagemaker"))), p

    created_at = time.monotonic()
    final_url, status = _fetch_final_url_or_code(ctx, url)
    assert status == 200, f"immediate use of the presigned URL failed with status {status}"
    assert _same_zone(final_url, url), (
        f"presigned URL redirected out of its own zone to {final_url!r} immediately after creation, "
        "well within its 5-minute TTL window"
    )

    # Two-sided: the URL must still be live well within the TTL (never advance to
    # "expired" early), then must have actually expired once the TTL has elapsed. Both
    # legs are bounded retries with a stated deadline, never a bare sleep.
    elapsed_at_checkpoint = _poll_until(
        lambda: time.monotonic() - created_at,
        lambda elapsed: elapsed >= _MID_WINDOW_CHECKPOINT_S,
        timeout_s=_MID_WINDOW_CHECKPOINT_S + 30.0,
        interval_s=30.0,
    )
    mid_window_url, mid_window_status = _fetch_final_url_or_code(ctx, url)
    assert _same_zone(mid_window_url, url), (
        f"presigned URL already redirected out of its own zone to {mid_window_url!r} at "
        f"{elapsed_at_checkpoint:.0f}s "
        f"(status {mid_window_status}), before its documented 5-minute TTL elapsed"
    )

    # _poll_until raises with the last (expired, status, url) probe on timeout, so a
    # never-expires target fails loudly with the observed status/url rather than a bare
    # boolean.
    _poll_until(
        lambda: _looks_expired(ctx, url),
        lambda v: v[0],
        timeout_s=(_URL_TTL_SECONDS - _MID_WINDOW_CHECKPOINT_S) + 600.0,
        interval_s=15.0,
    )

    # the notebook instance itself is unaffected by the URL's expiry
    described = sm.describe_notebook_instance(NotebookInstanceName=notebook_name)
    assert described["NotebookInstanceStatus"] == "InService", (
        f"expected the notebook instance to remain InService after its presigned URL "
        f"expired, got {described['NotebookInstanceStatus']!r}"
    )


def _same_zone(final_url, presigned_url) -> bool:
    """Whether a redirect chain ended in the presigned URL's own zone: every host label after the
    first (service label, region, domain) is the presigned host's. A hand-off to a sign-in page
    on another host is not, and the domain is compared, never named."""
    final = (urlsplit(final_url or "").hostname or "").split(".")
    origin = (urlsplit(presigned_url).hostname or "").split(".")
    return len(origin) > 2 and all(origin) and final[1:] == origin[1:]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never met within {timeout_s}s, last={last}")


def _fetch_final_url_or_code(ctx, url: str, timeout_s: float = 20.0):
    # The auth hop sets a session cookie and redirects to the notebook host, which needs it back;
    # without a cookie jar the notebook host bounces the request to the console instead.
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    try:
        with opener.open(_routed_request(ctx, url), timeout=timeout_s) as resp:
            return resp.geturl(), resp.status
    except urllib.error.HTTPError as e:
        return getattr(e, "url", None), e.code
    except urllib.error.URLError as e:
        raise AssertionError(f"could not reach presigned URL host: {e}") from e


def _looks_expired(ctx, url: str) -> tuple[bool, int, str | None]:
    final_url, status = _fetch_final_url_or_code(ctx, url)
    expired = status in (400, 403) or (bool(final_url) and not _same_zone(final_url, url))
    return expired, status, final_url


def _create_sagemaker_execution_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-behav-nbrole-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "sagemaker.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    )

    def _cleanup():
        try:
            iam.detach_role_policy(
                RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _is_gone(error: ClientError) -> bool:
    """DescribeNotebookInstance on a deleted instance: real AWS answers ValidationException
    ``RecordNotFound``."""
    err = error.response["Error"]
    return err["Code"] == "ResourceNotFound" or (
        err["Code"] == "ValidationException" and err.get("Message") == "RecordNotFound")


def _delete_notebook_instance_and_wait(sm, notebook_name, timeout_s=600.0, interval_s=15.0):
    try:
        described = sm.describe_notebook_instance(NotebookInstanceName=notebook_name)
    except ClientError as e:
        if _is_gone(e):
            return
        raise
    if described["NotebookInstanceStatus"] not in ("Stopped", "Failed"):
        sm.stop_notebook_instance(NotebookInstanceName=notebook_name)
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            described = sm.describe_notebook_instance(NotebookInstanceName=notebook_name)
            if described["NotebookInstanceStatus"] in ("Stopped", "Failed"):
                break
            time.sleep(interval_s)
    sm.delete_notebook_instance(NotebookInstanceName=notebook_name)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            sm.describe_notebook_instance(NotebookInstanceName=notebook_name)
        except ClientError as e:
            if _is_gone(e):
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"notebook instance {notebook_name} was not deleted within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
