"""notebook-mutations-throttle-too-many-requests."""
from __future__ import annotations

import json
import threading
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "notebook-mutations-throttle-too-many-requests"
GROUP = "error-semantics"
SERVICES = ["athena"]

# Depending on which layer throttles first, AWS may answer with any code botocore treats as
# throttling, not only the documented TooManyRequestsException; accept that family.
_THROTTLE_CODES = frozenset({
    "TooManyRequestsException",
    "ThrottlingException",
    "ThrottledException",
    "RequestThrottledException",
    "RequestThrottled",
    "RequestLimitExceeded",
    "SlowDown",
    "LimitExceededException",
    "PriorRequestNotComplete",
})


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Sustained concurrent CreateNotebook calls on one Spark workgroup trip the rate limit: at
    least one succeeds, at least one is throttled, and no other error code appears."""
    athena = ctx.client("athena")
    bucket = _create_bucket(ctx)
    # Real AWS rejects CreateWorkGroup for a Spark-enabled workgroup with
    # "ExecutionRole is null or empty" unless a real execution role ARN is provided.
    role_arn = _iam_role_for_spark(ctx)
    wg = ctx.unique_name("sim2real-behav-sparkwg-")
    _create_work_group_with_role_propagation_retry(
        athena,
        Name=wg,
        Configuration={
            "ResultConfiguration": {"OutputLocation": f"s3://{bucket}/"},
            "EngineVersion": {"SelectedEngineVersion": "PySpark engine version 3"},
            "ExecutionRole": role_arn,
        },
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))

    # Standard retry mode would silently retry away the throttle this check needs to see.
    no_retry_athena = _no_retry_client(ctx)

    created_ids: list[str] = []
    all_codes: list[str | None] = []
    lock = threading.Lock()
    stop_event = threading.Event()

    ctx.on_cleanup(lambda: _cleanup_notebooks(athena, created_ids))

    # The rate quota is a token bucket that refills between discrete bursts, so workers issue
    # calls back-to-back until the first throttle, bounded by the run budget less the teardown.
    CONCURRENCY = 120
    DEADLINE_S = _burst_window_s(ctx, 130.0)
    deadline = time.monotonic() + DEADLINE_S

    # Cap simultaneously alive notebooks well under the notebook-count quota, so only the
    # request-rate quota is exercised.
    OUTSTANDING_LIMIT = 8
    outstanding_sem = threading.Semaphore(OUTSTANDING_LIMIT)

    def _hammer(worker_id):
        local_i = 0
        while not stop_event.is_set() and time.monotonic() < deadline:
            local_i += 1
            if not outstanding_sem.acquire(timeout=1.0):
                continue
            try:
                try:
                    resp = no_retry_athena.create_notebook(
                        WorkGroup=wg,
                        Name=ctx.unique_name(f"sim2real-behav-nb-w{worker_id}-{local_i}-"),
                    )
                    nid = resp["NotebookId"]
                    with lock:
                        all_codes.append(None)
                    # Delete at once to stay clear of the count quota; track only on failure.
                    try:
                        athena.delete_notebook(NotebookId=nid)
                    except ClientError:
                        with lock:
                            created_ids.append(nid)
                except ClientError as e:
                    code = e.response["Error"]["Code"]
                    with lock:
                        all_codes.append(code)
                    if code in _THROTTLE_CODES:
                        stop_event.set()
                        return
            finally:
                outstanding_sem.release()

    threads = [threading.Thread(target=_hammer, args=(w,), daemon=True) for w in range(CONCURRENCY)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=max(0.0, deadline + 10.0 - time.monotonic()))

    succeeded = [c for c in all_codes if c is None]
    unexpected = [c for c in all_codes if c is not None and c not in _THROTTLE_CODES]
    throttled = [c for c in all_codes if c in _THROTTLE_CODES]

    # created_ids holds only notebooks whose immediate delete failed.
    assert len(created_ids) <= len(succeeded)
    assert not unexpected, f"unexpected error codes among concurrent CreateNotebook calls: {unexpected}"
    # Positive control: throttling every call is not the same as enforcing a rate limit.
    assert len(succeeded) >= 1, (
        f"positive control failed: no CreateNotebook call succeeded before throttling set "
        f"in ({len(all_codes)} calls attempted, all rejected) -- cannot distinguish "
        f"'enforces the sustained rate limit' from 'rejects every call'"
    )
    assert len(throttled) >= 1, (
        f"expected at least one throttling error (e.g. TooManyRequestsException) among "
        f"{len(all_codes)} sustained concurrent CreateNotebook calls ({CONCURRENCY} workers "
        f"hammering continuously for up to {DEADLINE_S:.0f}s with no inter-round pauses), got 0 "
        f"throttled ({len(succeeded)} succeeded)"
    )
    assert len(succeeded) + len(throttled) == len(all_codes)


def _burst_window_s(ctx, cap_s):
    """The burst's window: cap_s, bounded by the runner's remaining time less 20 s for the joins
    and the teardown, so the throttle assert reports its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 20.0))


def _iam_role_for_spark(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-athena-spark-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "athena.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policies = [
        "arn:aws:iam::aws:policy/AmazonAthenaFullAccess",
        "arn:aws:iam::aws:policy/AmazonS3FullAccess",
        "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess",
        "arn:aws:iam::aws:policy/AWSGlueConsoleFullAccess",
    ]
    for arn in policies:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
        ctx.on_cleanup(lambda a=arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=a))
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    return role_arn


def _create_work_group_with_role_propagation_retry(athena, *, timeout_s=90.0, interval_s=5.0, **kwargs):
    """Retry CreateWorkGroup while a just-created ExecutionRole is still propagating in IAM."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return athena.create_work_group(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "").lower()
            if code in ("InvalidRequestException", "AccessDeniedException") and (
                "role" in message or "authoriz" in message
            ):
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    raise last_err


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-athena-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup():
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _cleanup_notebooks(athena, notebook_ids):
    for nid in notebook_ids:
        try:
            athena.delete_notebook(NotebookId=nid)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (err.get("Code") == "InvalidRequestException" and "was not found" in err.get("Message", "")):
                raise


def _no_retry_client(ctx):
    """An athena client with retries disabled so a throttle surfaces as a raw exception.

    The large pool keeps urllib3's default maxsize=10 from serializing the burst."""
    return ctx.client(
        "athena", config=Config(retries={"max_attempts": 1}, max_pool_connections=2000)
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
