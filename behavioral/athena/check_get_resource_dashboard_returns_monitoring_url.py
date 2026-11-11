"""get-resource-dashboard-returns-monitoring-url."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-resource-dashboard-returns-monitoring-url"
GROUP = "server-side"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResourceDashboard returns an https URL for a ready session and rejects an unissued
    session ARN as not found; on this Spark engine version StartCalculationExecution is rejected
    as not authorized and the session stays IDLE."""
    from botocore.exceptions import ClientError

    athena = ctx.client("athena")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    setup = _setup_spark_workgroup(ctx)
    workgroup = setup["workgroup"]
    session_id = _start_session(ctx, workgroup)

    # A session ARN is nested under its workgroup (".../workgroup/<wg>/session/<id>"). The
    # dashboard registers asynchronously as the session becomes ready, so retry briefly.
    session_arn = (
        f"arn:aws:athena:{ctx.region}:{account_id}:workgroup/{workgroup}"
        f"/session/{session_id}"
    )
    dashboard = None
    last_err: ClientError | None = None
    deadline = time.monotonic() + 35.0
    while time.monotonic() < deadline:
        try:
            dashboard = athena.get_resource_dashboard(ResourceARN=session_arn)
            break
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidRequestException":
                raise
            last_err = err
            time.sleep(2.0)
    if dashboard is None:
        raise TimeoutError(f"dashboard for {session_arn} never became available: {last_err}")
    assert dashboard["Url"].startswith("https://"), (
        f"expected an https monitoring URL, got {dashboard['Url']!r}"
    )

    # AWS rejects calculations on the Spark engine version that GetResourceDashboard requires;
    # the dashboard URL above shows the session is otherwise healthy.
    code, message = _error(
        lambda: athena.start_calculation_execution(
            SessionId=session_id, CodeBlock="1"
        )
    )
    assert code == "InvalidRequestException", (
        f"expected StartCalculationExecution to be rejected as not authorized "
        f"on this Spark engine version, got {code!r}"
    )
    assert message == "Not authorized to make this request.", (
        f"unexpected StartCalculationExecution message: {message!r}"
    )

    # The rejected call must not have started a calculation: the session stays IDLE.
    state_after = athena.get_session_status(SessionId=session_id)["Status"]["State"]
    assert state_after == "IDLE", (
        f"expected the session to remain IDLE after the rejected calculation, got {state_after!r}"
    )

    # A well-formed ARN with an "s-<id>" session id that was never issued.
    import uuid

    bogus_session_id = f"s-{uuid.uuid4().hex[:16]}"
    bogus_arn = (
        f"arn:aws:athena:{ctx.region}:{account_id}:workgroup/{workgroup}"
        f"/session/{bogus_session_id}"
    )
    code, message = _error(lambda: athena.get_resource_dashboard(ResourceARN=bogus_arn))
    assert code == "InvalidRequestException", (
        f"expected InvalidRequestException for an unissued session id, got {code!r}"
    )
    assert message == "ResourceARN is not found", (
        f"unexpected GetResourceDashboard message: {message!r}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn(); return its ClientError (code, message), or fail if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call SUCCEEDED and returned {result!r}")


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    timeout_s: float = 300.0,
    interval_s: float = 10.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise TimeoutError(f"condition not met within {timeout_s}s; last={last!r}")


_SPARK_POLICIES = [
    "arn:aws:iam::aws:policy/AmazonAthenaFullAccess",
    "arn:aws:iam::aws:policy/AWSGlueConsoleFullAccess",
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess",
]


def _setup_spark_workgroup(ctx) -> dict[str, str]:
    from botocore.exceptions import ClientError

    athena = ctx.client("athena")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    role_name = ctx.unique_name("sim2real-athena-spark-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "athena.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]

    def _cleanup_role() -> None:
        for policy_arn in _SPARK_POLICIES:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)

    for policy_arn in _SPARK_POLICIES:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    bucket_name = ctx.unique_name("sim2real-athena-spark-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )

    def _cleanup_bucket() -> None:
        try:
            objs = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
            for obj in objs:
                s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
            s3.delete_bucket(Bucket=bucket_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise

    ctx.on_cleanup(_cleanup_bucket)

    # The Spark engine version string differs across accounts/partitions; read the advertised one.
    spark_version = None
    for ev in athena.list_engine_versions().get("EngineVersions", []):
        selected = ev.get("EngineVersion", ev).get("SelectedEngineVersion", "")
        if "Spark" in selected:
            spark_version = selected
            break
    if spark_version is None:
        raise AssertionError("no Spark-capable engine version advertised by ListEngineVersions")

    # CreateWorkGroup can reject a just-created ExecutionRole until IAM propagates, so retry
    # briefly on that failure; the check still has to fit a dashboard poll afterwards.
    # No ResultConfiguration: Athena rejects it on a Spark-engine workgroup; the role still needs
    # S3 access to `bucket_name` for Spark's working storage.
    workgroup = ctx.unique_name("sim2real-spark-wg-")
    wg_deadline = time.monotonic() + 30.0
    while True:
        try:
            athena.create_work_group(
                Name=workgroup,
                Configuration={
                    "ExecutionRole": role_arn,
                    "EngineVersion": {"SelectedEngineVersion": spark_version},
                },
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            break
        except ClientError as err:
            if time.monotonic() >= wg_deadline:
                raise AssertionError(
                    f"CreateWorkGroup never succeeded (role propagation?): {err}"
                ) from err
            time.sleep(5.0)

    def _cleanup_wg() -> None:
        try:
            athena.delete_work_group(WorkGroup=workgroup, RecursiveDeleteOption=True)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (err.get("Code") == "InvalidRequestException" and "not found" in err.get("Message", "")):
                raise

    ctx.on_cleanup(_cleanup_wg)

    return {"workgroup": workgroup, "bucket": bucket_name, "role_arn": role_arn}


def _start_session(ctx, workgroup: str, extra_engine_config: dict[str, Any] | None = None, **kwargs) -> str:
    from botocore.exceptions import ClientError

    athena = ctx.client("athena")
    # No CoordinatorDpuSize/MaxConcurrentDpus/DefaultExecutorDpuSize: Athena rejects each as
    # "not supported for this engine configuration"; the engine version fixes DPU sizing.
    engine_configuration: dict[str, Any] = {}
    if extra_engine_config:
        engine_configuration.update(extra_engine_config)

    # Retry briefly to absorb residual IAM role/workgroup propagation delay.
    last_err = None
    session_id = None
    for _ in range(3):
        try:
            resp = athena.start_session(
                WorkGroup=workgroup, EngineConfiguration=engine_configuration, **kwargs
            )
            session_id = resp["SessionId"]
            break
        except ClientError as err:
            last_err = err
            time.sleep(5.0)
    if session_id is None:
        raise AssertionError(f"StartSession never succeeded (role propagation?): {last_err}")

    def _cleanup_session() -> None:
        try:
            st = athena.get_session_status(SessionId=session_id)["Status"]["State"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        if st not in ("TERMINATED", "TERMINATING", "FAILED"):
            try:
                athena.terminate_session(SessionId=session_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise

    ctx.on_cleanup(_cleanup_session)

    # Spark session startup can take a couple of minutes, but the check still has work to do
    # after IDLE, so the bound is generous yet not maximal.
    try:
        _poll_until(
            lambda: athena.get_session_status(SessionId=session_id)["Status"],
            lambda st: st["State"] in ("IDLE", "FAILED", "DEGRADED"),
            timeout_s=200.0,
            interval_s=10.0,
        )
    except TimeoutError:
        raise AssertionError("session did not leave CREATING within timeout")

    final_state = athena.get_session_status(SessionId=session_id)["Status"]["State"]
    if final_state != "IDLE":
        raise AssertionError(f"session reached {final_state} instead of IDLE (environment issue)")

    return session_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
