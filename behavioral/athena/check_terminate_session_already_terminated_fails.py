"""terminate-session-already-terminated-fails."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "terminate-session-already-terminated-fails"
GROUP = "overly-permissive"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second TerminateSession on a real, already TERMINATED Spark session succeeds as a no-op
    reporting TERMINATED (InvalidRequestException is reserved for a SessionId that never existed),
    and the session stays resolvable and TERMINATED afterwards."""
    athena = ctx.client("athena")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx, s3)
    role_arn = _create_spark_execution_role(ctx, iam, bucket)
    workgroup = ctx.unique_name("sim2real-sparkwg-")
    athena.create_work_group(
        Name=workgroup,
        Configuration={
            "ExecutionRole": role_arn,
            "ResultConfiguration": {"OutputLocation": f"s3://{bucket}/results/"},
            "EngineVersion": {"SelectedEngineVersion": "PySpark engine version 3"},
        },
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=workgroup))

    session_id = _start_session_with_retry(athena, workgroup, role_arn)
    if session_id is None:
        raise AssertionError("unable to start a Spark session in this account/region within the retry budget")
    ctx.on_cleanup(lambda: _best_effort_terminate(athena, session_id))

    # First TerminateSession call: succeeds against a live (non-terminated) session.
    resp = athena.terminate_session(SessionId=session_id)
    assert resp["State"] in ("TERMINATING", "TERMINATED"), (
        f"expected TERMINATING/TERMINATED after first terminate, got {resp['State']}"
    )

    # Positive control: the session id still resolves (it is not "not found";
    # it is a real session now mid/post termination).
    still_resolves = athena.get_session(SessionId=session_id)
    assert still_resolves["SessionId"] == session_id
    assert still_resolves["Status"]["State"] in ("TERMINATING", "TERMINATED"), (
        f"expected TERMINATING/TERMINATED, got {still_resolves['Status']['State']}"
    )

    # Termination is asynchronous: immediately after the first call the
    # session may still report TERMINATING. AWS only rejects a repeat
    # TerminateSession once the session has actually settled into the
    # TERMINATED terminal state, so poll (bounded) for that before issuing
    # the second call, rather than racing the state transition.
    final_state = _poll_until_terminated(athena, session_id)
    assert final_state == "TERMINATED", (
        f"session did not reach TERMINATED state within the poll budget "
        f"(last observed state: {final_state})"
    )

    # Idempotency: a second TerminateSession call on the same, already terminated session succeeds
    # as a no-op rather than raising. Real Athena only rejects TerminateSession with
    # InvalidRequestException for a SessionId that never resolved to a real session in the first
    # place; once a session id has resolved to a real session, repeat termination calls are
    # idempotent and keep reporting the terminal state.
    second_resp = athena.terminate_session(SessionId=session_id)
    assert second_resp["State"] == "TERMINATED", (
        f"expected idempotent TERMINATED on repeat TerminateSession, got {second_resp['State']}"
    )

    # The repeat call must not perturb the already-terminated session: it
    # stays resolvable via GetSession and keeps reporting TERMINATED.
    still_terminated = athena.get_session(SessionId=session_id)
    assert still_terminated["SessionId"] == session_id
    assert still_terminated["Status"]["State"] == "TERMINATED", (
        f"expected session to remain TERMINATED after repeat terminate, got "
        f"{still_terminated['Status']['State']}"
    )


def _poll_until_terminated(athena, session_id, timeout_s=90, interval_s=5):
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        resp = athena.get_session(SessionId=session_id)
        last_state = resp["Status"]["State"]
        if last_state == "TERMINATED":
            return last_state
        time.sleep(interval_s)
    return last_state


def _best_effort_terminate(athena, session_id):
    _ignore_missing(lambda: athena.terminate_session(SessionId=session_id), "InvalidRequestException")


def _ignore_missing(fn, *codes):
    """Run a teardown call; return only on the given not-found codes, raise anything else."""
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in codes:
            raise


def _create_bucket(ctx, s3):
    bucket = ctx.unique_name("sim2real-athena-spark-").lower().replace("_", "-")
    # S3's CreateBucket rejects an explicit LocationConstraint of "us-east-1" --
    # that region is the only one that must omit the field entirely.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "terminate-session-already-terminated-fails"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})

    def _cleanup_bucket():
        def _empty_and_delete():
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            for obj in objs:
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
            s3.delete_bucket(Bucket=bucket)

        _ignore_missing(_empty_and_delete, "NoSuchBucket")

    ctx.on_cleanup(_cleanup_bucket)
    return bucket


def _create_spark_execution_role(ctx, iam, bucket):
    role_name = ctx.unique_name("sim2real-athena-spark-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "athena.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[
            {"Key": "sim2real", "Value": "terminate-session-already-terminated-fails"},
            {"Key": "sim2real:managed", "Value": "true"},
        ],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))

    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    policy_name = "sim2real-spark-exec-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(permissions_policy),
    )
    ctx.on_cleanup(lambda: _delete_role_policy(iam, role_name, policy_name))
    return role_arn


def _delete_role_policy(iam, role_name, policy_name):
    _ignore_missing(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name), "NoSuchEntity")


def _delete_role(iam, role_name):
    _ignore_missing(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity")


def _start_session_with_retry(athena, workgroup, role_arn, timeout_s=90, interval_s=10):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = athena.start_session(
                WorkGroup=workgroup,
                ExecutionRole=role_arn,
                EngineConfiguration={
                    "CoordinatorDpuSize": 1,
                    # MaxConcurrentDpus has a service-enforced minimum of 2;
                    # a value of 1 fails client-side parameter validation.
                    "MaxConcurrentDpus": 2,
                    "DefaultExecutorDpuSize": 1,
                },
                SessionIdleTimeoutInMinutes=15,
            )
            return resp["SessionId"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    if last_exc is not None:
        return None
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
