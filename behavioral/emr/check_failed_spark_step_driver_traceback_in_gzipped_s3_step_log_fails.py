"""failed-spark-step-driver-traceback-in-gzipped-s3-step-log-fails."""
from __future__ import annotations

import gzip
import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "failed-spark-step-driver-traceback-in-gzipped-s3-step-log-fails"
GROUP = "negative-classes"
SERVICES = ["emr"]

INSTANCE_TYPE = "m5.xlarge"
RELEASE_LABEL = "emr-6.15.0"

# One overall deadline for the strictly sequential phases, leaving room for the inline teardown.
_TOTAL_BUDGET_S = 1620.0
_STEPS_BUDGET_S = 780.0
_TEARDOWN_BUDGET_S = 360.0

_EMR_SERVICE_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "elasticmapreduce.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
_EC2_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "ec2.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
# The v1 service policy: AmazonEMRServicePolicy_v2 only reaches network resources tagged
# `for-use-with-amazon-emr-managed-policies`.
_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"

# A `command-runner.jar spark-submit` step's log directory holds these objects (no syslog.gz).
_EXPECTED_STEP_LOG_KEYS = frozenset({"controller.gz", "stderr.gz", "stdout.gz"})
_STEP_LOG_BUDGET_S = 600.0

# `ok` writes the nonce to S3; `boom` raises inside the driver with the nonce in the message, so
# the nonce can only reach S3 if a real driver ran and EMR captured its output.
_SPARK_JOB = '''\
import sys

from pyspark.sql import SparkSession

mode, out_uri, nonce = sys.argv[1:4]
spark = SparkSession.builder.appName("sim2real-emr-step-failure").getOrCreate()

if mode == "ok":
    spark.sparkContext.parallelize([nonce], 1).saveAsTextFile(out_uri)
    spark.stop()
else:
    try:
        spark.read.parquet(out_uri + "/dt=2099-01-01").count()
    except Exception as exc:
        spark.stop()
        raise RuntimeError("sim2real-marker-" + nonce) from exc
    spark.stop()
    raise RuntimeError("sim2real-marker-" + nonce + " (missing path unexpectedly readable)")
'''


class _Deadline:
    """A single wall-clock budget shared by every phase."""

    def __init__(self, total_s: float) -> None:
        self.end = time.monotonic() + total_s

    def left(self, cap_s: float) -> float:
        return max(0.0, min(cap_s, self.end - time.monotonic()))


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_with_retry(fn, attempts: int = 6, delay: float = 10.0) -> None:
    """Run an IAM delete, retrying DeleteConflict.

    IAM can briefly still see the instance profile as in use after the cluster is TERMINATED.
    """
    for i in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001
            if "DeleteConflict" not in str(exc) or i == attempts - 1:
                raise
            time.sleep(delay)


def _ensure_emr_roles(ctx, iam) -> tuple[str, str]:
    """Create the EMR service role and the EC2 instance profile, both deleted on teardown."""
    svc_role = ctx.unique_name("sim2real-emr-svc-")
    ec2_role = ctx.unique_name("sim2real-emr-ec2-")
    iam.create_role(RoleName=svc_role, AssumeRolePolicyDocument=_EMR_SERVICE_TRUST)
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=svc_role)))
    iam.attach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY))

    iam.create_role(RoleName=ec2_role, AssumeRolePolicyDocument=_EC2_TRUST)
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=ec2_role)))
    iam.attach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY))

    # RunJobFlow's JobFlowRole is an INSTANCE PROFILE name, not a role name.
    iam.create_instance_profile(InstanceProfileName=ec2_role)
    ctx.on_cleanup(lambda: _delete_with_retry(
        lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role)))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=ec2_role, RoleName=ec2_role))

    # Nothing observable says EMR can see the profile; RunJobFlow's retry below is the wait.
    return svc_role, ec2_role


def _retry_ec2_delete(fn, budget_s: float = 300.0) -> None:
    """Run an EC2 teardown call, retrying while its target is still held by something winding down."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001 — teardown retry/classification only
            code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
            if code.endswith(".NotFound"):
                return
            if code not in ("DependencyViolation", "InvalidNetworkInterface.InUse") or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _delete_vpc(ec2, vpc_id: str) -> None:
    """Delete the VPC after its non-default security groups: EMR creates its managed primary/core
    groups in it, and they reference each other, so their rules are revoked before the deletes."""
    groups = [
        g for g in ec2.describe_security_groups(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["SecurityGroups"]
        if g["GroupName"] != "default"
    ]
    for g in groups:
        if g.get("IpPermissions"):
            ec2.revoke_security_group_ingress(GroupId=g["GroupId"], IpPermissions=g["IpPermissions"])
        if g.get("IpPermissionsEgress"):
            ec2.revoke_security_group_egress(GroupId=g["GroupId"], IpPermissions=g["IpPermissionsEgress"])
    for g in groups:
        _retry_ec2_delete(lambda gid=g["GroupId"]: ec2.delete_security_group(GroupId=gid))
    _retry_ec2_delete(lambda: ec2.delete_vpc(VpcId=vpc_id))


def _pick_subnet(ctx, ec2) -> str:
    """A public subnet in a new VPC, in an available AZ that offers the instance type.

    The internet gateway and default route give the instances S3 egress for the step logs.
    """
    offered = {
        o["Location"] for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [INSTANCE_TYPE]}],
        )["InstanceTypeOfferings"]
    }
    usable = sorted(
        z["ZoneName"] for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered
    )
    assert usable, f"no available AZ offers {INSTANCE_TYPE}; offerings were {sorted(offered)!r}"

    vpc_id = ec2.create_vpc(CidrBlock="10.96.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc(ec2, vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-emr-fail-")}])

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.96.1.0/24", AvailabilityZone=usable[0])["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_ec2_delete(lambda: ec2.delete_subnet(SubnetId=subnet_id)))
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})

    igw_id = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _retry_ec2_delete(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id)))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: _retry_ec2_delete(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)))

    rt_id = ec2.create_route_table(VpcId=vpc_id)["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _retry_ec2_delete(lambda: ec2.delete_route_table(RouteTableId=rt_id)))
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    assoc_id = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)["AssociationId"]
    ctx.on_cleanup(lambda: _retry_ec2_delete(lambda: ec2.disassociate_route_table(AssociationId=assoc_id)))
    return subnet_id


def _create_bucket(ctx, s3, bucket: str) -> None:
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _purge_and_delete() -> None:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objs = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objs:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_purge_and_delete)


def _cluster_is_gone(exc) -> bool:
    """True only for the error meaning the cluster no longer exists.

    EMR has no ClusterNotFound: describing a reaped cluster is InvalidRequestException.
    """
    code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
    return (code in ("InvalidRequestException", "ClusterNotFound", "ResourceNotFoundException")
            or "is not valid" in str(exc) or "does not exist" in str(exc))


def _terminate_and_verify(emr, cluster_id: str, budget_s: float, *, raise_on_leak: bool = False) -> str:
    """Terminate and wait for the termination to finish; return the terminal state observed.
    With ``raise_on_leak`` (the registered cleanup) a cluster that never terminates raises.

    Inline, not via on_cleanup: EMR winds the cluster down for minutes, beyond the 60s cleanup cap.
    """
    try:
        emr.terminate_job_flows(JobFlowIds=[cluster_id])
    except Exception as exc:  # noqa: BLE001
        if not _cluster_is_gone(exc):
            raise
    deadline = time.monotonic() + budget_s
    last = "UNKNOWN"
    seen = None
    while time.monotonic() < deadline:
        try:
            last = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        except ClientError as exc:
            if _cluster_is_gone(exc):
                return "GONE"
            raise
        if last in ("TERMINATED", "TERMINATED_WITH_ERRORS"):
            return last
        seen = last
        time.sleep(2)
    if raise_on_leak:
        raise RuntimeError(f"EMR cluster {cluster_id} was not deleted: {seen!r}")
    return last


def _list_keys(s3, bucket: str, prefix: str) -> list[str]:
    out = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        out.extend(o["Key"] for o in page.get("Contents", []))
    return sorted(out)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e",
      "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Spark step that raises in the driver is FAILED and its gzipped S3 step logs contain this
    run's nonce, a Python traceback and a non-zero exit, while a control step that COMPLETED has
    logs with a zero exit and no traceback, and the failed step wrote no output.
    """
    emr = ctx.client("emr")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    clock = _Deadline(_budget_s(ctx, _TOTAL_BUDGET_S))
    nonce = uuid.uuid4().hex
    marker = f"sim2real-marker-{nonce}"

    bucket = ctx.unique_name("sim2real-emr-fail-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)
    s3.put_object(Bucket=bucket, Key="job/step.py", Body=_SPARK_JOB.encode("utf-8"))

    svc_role, ec2_profile = _ensure_emr_roles(ctx, iam)
    subnet_id = _pick_subnet(ctx, ec2)

    ok_out = f"s3://{bucket}/out/ok"
    boom_out = f"s3://{bucket}/out/boom"

    def _step(name: str, mode: str, out_uri: str) -> dict:
        return {
            "Name": name,
            # CONTINUE, so step B still runs after A and A's success is not why B ran.
            "ActionOnFailure": "CONTINUE",
            "HadoopJarStep": {
                "Jar": "command-runner.jar",
                "Args": ["spark-submit", "--deploy-mode", "client",
                         f"s3://{bucket}/job/step.py", mode, out_uri, nonce],
            },
        }

    last_exc = None
    cluster_id = None
    deadline = time.monotonic() + clock.left(240.0)
    while True:
        try:
            cluster_id = emr.run_job_flow(
                Name=ctx.unique_name("sim2real-emr-fail-cluster-"),
                ReleaseLabel=RELEASE_LABEL,
                LogUri=f"s3://{bucket}/logs/",
                Applications=[{"Name": "Spark"}],
                Instances={
                    "InstanceCount": 2,
                    "MasterInstanceType": INSTANCE_TYPE,
                    "SlaveInstanceType": INSTANCE_TYPE,
                    "Ec2SubnetId": subnet_id,
                    # EMR's step-log push agent only runs on a live cluster.
                    "KeepJobFlowAliveWhenNoSteps": True,
                    "TerminationProtected": False,
                },
                ServiceRole=svc_role,
                JobFlowRole=ec2_profile,
                VisibleToAllUsers=True,
                StepConcurrencyLevel=1,
                Steps=[_step("sim2real-ok", "ok", ok_out),
                       _step("sim2real-boom", "boom", boom_out)],
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )["JobFlowId"]
            break
        except Exception as exc:  # noqa: BLE001
            lowered = str(exc).lower()
            if not any(t in lowered for t in
                       ("throttl", "rate exceeded", "invalid instanceprofile", "invalid ec2")):
                raise
            last_exc = exc
            if time.monotonic() >= deadline:
                break
            time.sleep(2)
    if not cluster_id and _budget_spent(ctx):
        raise TimeoutError("RunJobFlow succeeding: the run budget ended first; not graded")
    assert cluster_id, f"RunJobFlow never succeeded: {last_exc}"
    # Failure-path net only; the verified teardown is inline in the finally below.
    ctx.on_cleanup(lambda: _terminate_and_verify(emr, cluster_id, 45.0, raise_on_leak=True))

    body_ok = False
    try:
        terminal = {"COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"}

        def _steps() -> list[dict]:
            out = []
            for page in emr.get_paginator("list_steps").paginate(ClusterId=cluster_id):
                out.extend(page.get("Steps", []))
            return out

        steps = _poll_until(
            _steps,
            lambda ss: len(ss) == 2 and all(s["Status"]["State"] in terminal for s in ss),
            timeout_s=clock.left(_STEPS_BUDGET_S),
            interval_s=2.0,
            ctx=ctx,
            description=f"both steps on cluster {cluster_id} reaching a terminal state",
        )
        by_name = {s["Name"]: s for s in steps}
        assert set(by_name) == {"sim2real-ok", "sim2real-boom"}, (
            f"unexpected step set on the cluster: {sorted(by_name)!r}"
        )
        step_ok = emr.describe_step(
            ClusterId=cluster_id, StepId=by_name["sim2real-ok"]["Id"])["Step"]
        step_boom = emr.describe_step(
            ClusterId=cluster_id, StepId=by_name["sim2real-boom"]["Id"])["Step"]

        # Positive control.
        assert step_ok["Status"]["State"] == "COMPLETED", (
            f"the control step ended {step_ok['Status']['State']!r} "
            f"({step_ok['Status'].get('FailureDetails')!r}) — the fixture is broken, so the failure "
            f"below would say nothing about EMR"
        )
        ok_parts = [k for k in _list_keys(s3, bucket, "out/ok/") if "/part-" in k]
        assert len(ok_parts) == 1, (
            f"control step wrote {len(ok_parts)} part files, expected 1: {ok_parts!r}"
        )
        ok_body = s3.get_object(Bucket=bucket, Key=ok_parts[0])["Body"].read().decode().strip()
        assert ok_body == nonce, (
            f"control step's object contains {ok_body!r}, expected this run's nonce {nonce!r}"
        )

        assert step_boom["Status"]["State"] == "FAILED", (
            f"the driver-exception step ended {step_boom['Status']['State']!r}, expected FAILED"
        )

        boom_prefix = f"logs/{cluster_id}/steps/{step_boom['Id']}/"
        ok_prefix = f"logs/{cluster_id}/steps/{step_ok['Id']}/"
        boom_keys = _poll_until(
            lambda: _list_keys(s3, bucket, boom_prefix),
            lambda keys: set(_EXPECTED_STEP_LOG_KEYS) <= {k.rsplit("/", 1)[1] for k in keys},
            timeout_s=clock.left(_STEP_LOG_BUDGET_S),
            interval_s=2.0,
            ctx=ctx,
            description=(
                f"EMR pushing at least {sorted(_EXPECTED_STEP_LOG_KEYS)!r} to "
                f"s3://{bucket}/{boom_prefix}"
            ),
        )
        by_base = {k.rsplit("/", 1)[1]: k for k in boom_keys}

        for base, key in sorted(by_base.items()):
            size = s3.head_object(Bucket=bucket, Key=key)["ContentLength"]
            assert size > 0, (
                f"{key!r} is empty — an emulator that touches a filename passes a listing count "
                f"and fails this"
            )
            first2 = s3.get_object(Bucket=bucket, Key=key, Range="bytes=0-1")["Body"].read()
            assert first2 == b"\x1f\x8b", (
                f"{key!r} does not start with the gzip magic, got {first2!r} ({base} is documented "
                f"as gzip-compressed)"
            )

        # Log objects are created early and appended on each ~5-minute push, so poll for the
        # content, not the keys. AWS documents no stream for the traceback, so read both.
        def _step_log_text(base: str) -> str:
            return gzip.decompress(
                s3.get_object(Bucket=bucket, Key=by_base[base])["Body"].read()
            ).decode("utf-8", errors="replace")

        def _driver_text() -> str:
            return _step_log_text("stdout.gz") + "\n" + _step_log_text("stderr.gz")

        driver_text = ""
        _deadline = time.monotonic() + clock.left(_STEP_LOG_BUDGET_S)
        while time.monotonic() < _deadline:
            driver_text = _driver_text()
            if marker in driver_text:
                break
            time.sleep(2)
        if marker not in driver_text and _budget_spent(ctx):
            raise TimeoutError(f"the step logs containing {marker!r}: the run budget ended first; not graded")
        assert marker in driver_text, (
            f"neither stdout.gz nor stderr.gz under s3://{bucket}/{boom_prefix} came to contain this "
            f"run's own marker {marker!r} — the driver's output was not captured. Per-file marker "
            f"presence and size: "
            f"{ {b: (marker in _step_log_text(b), len(_step_log_text(b))) for b in sorted(by_base)} !r}."
            f" tail: {driver_text[-1200:]!r}"
        )
        assert "Traceback (most recent call last)" in driver_text, (
            f"the failing step's stdout.gz/stderr.gz carry no Python traceback "
            f"(tail: {driver_text[-1200:]!r})"
        )
        assert "RuntimeError" in driver_text, (
            f"the failing step's stdout.gz/stderr.gz do not name the raised exception class "
            f"(tail: {driver_text[-1200:]!r})"
        )

        stderr_text = _step_log_text("stderr.gz")
        assert "Command exiting with ret '1'" in stderr_text, (
            f"{by_base['stderr.gz']!r} does not record the step's non-zero exit code "
            f"(tail: {stderr_text[-800:]!r})"
        )

        controller_text = _step_log_text("controller.gz")
        assert "spark-submit" in controller_text and "boom" in controller_text, (
            f"{by_base['controller.gz']!r} does not record the spark-submit invocation with the "
            f"'boom' argument (tail: {controller_text[-800:]!r})"
        )

        # The two steps' logs must be different bytes, not one canned template.
        ok_log_keys = _poll_until(
            lambda: _list_keys(s3, bucket, ok_prefix),
            lambda keys: any(
                "Command exiting with ret '0'" in gzip.decompress(
                    s3.get_object(Bucket=bucket, Key=k)["Body"].read()
                ).decode("utf-8", errors="replace")
                for k in keys
            ),
            timeout_s=clock.left(_STEP_LOG_BUDGET_S),
            interval_s=2.0,
            ctx=ctx,
            description=(
                f"the CONTROL step's own logs under s3://{bucket}/{ok_prefix} recording a ZERO exit "
                f"code — the two steps must not share one log"
            ),
        )
        ok_text = "".join(
            gzip.decompress(s3.get_object(Bucket=bucket, Key=k)["Body"].read())
            .decode("utf-8", errors="replace")
            for k in ok_log_keys
        )
        assert marker not in ok_text, (
            f"the CONTROL step's logs {ok_log_keys!r} also contain {marker!r} — the backend is "
            f"serving one log for both steps"
        )
        assert "Traceback (most recent call last)" not in ok_text, (
            f"the CONTROL step's logs carry a Python traceback even though the step COMPLETED "
            f"(tail: {ok_text[-800:]!r})"
        )
        assert "Command exiting with ret '1'" not in ok_text, (
            f"the CONTROL step's logs record a non-zero exit code even though the step COMPLETED "
            f"(tail: {ok_text[-800:]!r})"
        )

        boom_out_keys = _list_keys(s3, bucket, "out/boom/")
        assert boom_out_keys == [], (
            f"the failing step still wrote output objects: {boom_out_keys!r}"
        )
        body_ok = True
    finally:
        # Assert the teardown only when the body succeeded, so it never masks the real failure.
        state = _terminate_and_verify(emr, cluster_id, _budget_s(ctx, _TEARDOWN_BUDGET_S))
        if body_ok:
            if state not in ("TERMINATED", "TERMINATED_WITH_ERRORS", "GONE") and _budget_spent(ctx):
                raise TimeoutError(f"cluster {cluster_id} terminating: the run budget ended first; not graded")
            assert state in ("TERMINATED", "TERMINATED_WITH_ERRORS", "GONE"), (
                f"cluster {cluster_id} is still {state!r} after the verified teardown wait — every "
                f"provisioned m5.xlarge is ~$173/mo and reap_leftovers.py cannot terminate it"
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
