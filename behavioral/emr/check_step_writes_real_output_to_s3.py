"""step-writes-real-output-to-s3."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "step-writes-real-output-to-s3"
GROUP = 'data-plane'
SERVICES = ['emr']

# ===== helpers =====

INSTANCE_TYPE = "m5.xlarge"
RELEASE_LABEL = "emr-6.15.0"

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
# The legacy service policy, deliberately, NOT AmazonEMRServicePolicy_v2: v2 only grants EMR access
# to network resources carrying the `for-use-with-amazon-emr-managed-policies` tag, so it would make
# this check depend on the account's default VPC being pre-tagged.
_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"
IDLE_TIMEOUT_S = 60

MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

TERMINAL_CLUSTER_STATES = {"TERMINATED", "TERMINATED_WITH_ERRORS"}
TERMINAL_STEP_STATES = {"COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"}


def _swallow(fn):
    """Run a teardown call fn(), tolerating only a cluster that is gone or already shut down."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            not (err["Code"] == "InvalidRequestException" and "is not valid" in err.get("Message", ""))
            and not (err["Code"] == "ValidationException" and "Specified job flow ID not valid" in err.get("Message", ""))
            and not (err["Code"] == "ValidationException" and "may not be modified" in err.get("Message", ""))
        ):
            raise


def _poll(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _cluster_state(emr, cluster_id):
    return emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]


def _register_cluster_cleanup(ctx, emr, cluster_id) -> None:
    """Register teardown for cluster_id. MUST be called before the id is used."""

    def _cleanup() -> None:
        _swallow(
            lambda: emr.set_termination_protection(
                JobFlowIds=[cluster_id], TerminationProtected=False
            )
        )
        _swallow(lambda: emr.terminate_job_flows(JobFlowIds=[cluster_id]))
        _swallow(
            lambda: _poll(
                lambda: _cluster_state(emr, cluster_id),
                lambda s: s in TERMINAL_CLUSTER_STATES,
                timeout_s=600,
                interval_s=2,
                description=f"cluster {cluster_id} reaches a terminal state",
            )
        )

    ctx.on_cleanup(_cleanup)


def _make_bucket(ctx, s3):
    """Create a log/output bucket and register its (recursive) teardown.

    Registered BEFORE the cluster, so the LIFO cleanup order tears the cluster
    down first — EMR keeps writing logs to the bucket until it is TERMINATED and
    a non-empty bucket cannot be deleted.
    """
    bucket = ctx.unique_name("sim2real-behav-emr-out-")

    def _cleanup() -> None:
        def _purge_and_delete() -> None:
            paginator = s3.get_paginator("list_object_versions")
            for page in paginator.paginate(Bucket=bucket):
                victims = [
                    {"Key": o["Key"], "VersionId": o["VersionId"]}
                    for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
                ]
                if victims:
                    failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": victims}).get("Errors")
                    if failed:
                        raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            s3.delete_bucket(Bucket=bucket)

        _swallow(_purge_and_delete)

    ctx.on_cleanup(_cleanup)
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    return bucket


def _delete_with_retry(fn, attempts=6, delay=10):
    """Run an IAM delete, retrying DeleteConflict.

    Even once the cluster reports TERMINATED, IAM can briefly still see the instance
    profile as in use. The runner swallows teardown errors, so without a retry the only
    symptom of losing that race would be a leaked role nobody looks at.
    """
    for i in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001
            if "DeleteConflict" not in str(exc) or i == attempts - 1:
                raise
            time.sleep(delay)


def _ensure_emr_roles(ctx):
    """Provision the service role + EC2 instance profile EMR needs. Returns (service_role, ec2_role).

    The roles are created in-check and deleted on teardown.
    """
    iam = ctx.client("iam")
    svc_role = ctx.unique_name("sim2real-behav-emr-svc-")
    ec2_role = ctx.unique_name("sim2real-behav-emr-ec2-")
    # Cleanups run LIFO, so registering each teardown immediately after its create yields the
    # only order IAM accepts: remove-from-profile, delete profile, detach policies, delete roles.
    try:
        iam.create_role(RoleName=svc_role, AssumeRolePolicyDocument=_EMR_SERVICE_TRUST)
        ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=svc_role)))
        iam.attach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY))

        iam.create_role(RoleName=ec2_role, AssumeRolePolicyDocument=_EC2_TRUST)
        ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=ec2_role)))
        iam.attach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY))

        # RunJobFlow's JobFlowRole is an INSTANCE PROFILE name, not a role name; give it the
        # same name as its role, which is the convention EMR's own default roles follow.
        iam.create_instance_profile(InstanceProfileName=ec2_role)
        ctx.on_cleanup(lambda: _delete_with_retry(
            lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role)))
        iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
        ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=ec2_role, RoleName=ec2_role))
    except Exception as exc:  # noqa: BLE001
        # Nothing can be attributed to EMR if its prerequisites cannot be built.
        raise AssertionError(
            f"cannot provision the EMR service role / EC2 instance profile: {exc}"
        ) from exc

    # IAM is eventually consistent; EMR rejects a role/profile it cannot see yet. RunJobFlow
    # also retries "invalid InstanceProfile" below, so this only shortens that retry loop —
    # but the wait itself is bounded on IAM's own answer, not a flat sleep.
    _poll(
        lambda: _roles_visible(iam, svc_role, ec2_role),
        lambda visible: visible,
        timeout_s=60,
        interval_s=5,
        description=f"IAM role {svc_role} and instance profile {ec2_role} to become visible",
    )
    return svc_role, ec2_role


def _launch_cluster(
    ctx, emr, *, keep_alive: bool, service_role: str, job_flow_role: str, steps=None, **overrides
):
    """RunJobFlow the cheapest cluster that can prove a data-plane invariant."""
    name = ctx.unique_name("sim2real-behav-emr-cluster-")
    params = dict(
        Name=name,
        ReleaseLabel=RELEASE_LABEL,
        Instances={
            "InstanceGroups": [
                {
                    "Name": "Primary",
                    "InstanceRole": "MASTER",
                    "InstanceType": INSTANCE_TYPE,
                    "InstanceCount": 1,
                    "Market": "ON_DEMAND",
                }
            ],
            "KeepJobFlowAliveWhenNoSteps": keep_alive,
            "TerminationProtected": False,
        },
        Applications=[{"Name": "Hadoop"}],
        JobFlowRole=job_flow_role,
        ServiceRole=service_role,
        VisibleToAllUsers=True,
        Tags=MANAGED_TAGS,
        AutoTerminationPolicy={"IdleTimeout": IDLE_TIMEOUT_S},
    )
    if steps is not None:
        params["Steps"] = steps
    params.update(overrides)

    left = ctx.time_left()
    deadline = time.monotonic() + (320 if left is None else min(320, left))
    while True:
        try:
            resp = emr.run_job_flow(**params)
            break
        except Exception as exc:  # noqa: BLE001 — classified below, re-raised if fatal
            lowered = str(exc).lower()
            transient = (
                "throttl" in lowered
                or "rate exceeded" in lowered
                or "invalid instanceprofile" in lowered
                or "invalid ec2" in lowered
            )
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(2)

    cluster_id = resp["JobFlowId"]
    _register_cluster_cleanup(ctx, emr, cluster_id)  # BEFORE the id is used anywhere
    return cluster_id, name


def _step_state(emr, cluster_id, step_id):
    return emr.describe_step(ClusterId=cluster_id, StepId=step_id)["Step"]["Status"]["State"]


def _roles_visible(iam, svc_role, ec2_role):
    """True once IAM itself reports both the service role and the instance profile."""
    try:
        iam.get_role(RoleName=svc_role)
        iam.get_instance_profile(InstanceProfileName=ec2_role)
    except ClientError:
        return False
    return True


# ===== end helpers =====


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EMR step really executes the customer's command: the object it writes to S3 holds
    exactly the nonce it was given, and EMR ships the step's logs to LogUri."""
    emr = ctx.client("emr")
    s3 = ctx.client("s3")
    # Registered first, so LIFO tears the cluster down before the IAM roles it assumes.
    service_role, job_flow_role = _ensure_emr_roles(ctx)

    bucket = _make_bucket(ctx, s3)
    key = "step-output/result.txt"
    nonce = ctx.unique_name("emr-nonce-")

    step = {
        "Name": "sim2real-behav-emr-write-nonce",
        "ActionOnFailure": "TERMINATE_CLUSTER",
        "HadoopJarStep": {
            "Jar": "command-runner.jar",
            "Args": [
                "bash",
                "-c",
                # printf (not echo) so there is no trailing newline ambiguity to assert around.
                f"printf %s '{nonce}' > /tmp/result.txt && "
                f"aws s3 cp /tmp/result.txt s3://{bucket}/{key}",
            ],
        },
    }

    # keep_alive=False: the cluster self-terminates the moment the step finishes,
    # which is both the cheapest shape and a second cost guard on top of the
    # AutoTerminationPolicy and the registered teardown.
    cluster_id, _ = _launch_cluster(
        ctx,
        emr,
        keep_alive=False,
        service_role=service_role,
        job_flow_role=job_flow_role,
        steps=[step],
        LogUri=f"s3://{bucket}/logs/",
    )

    steps = emr.list_steps(ClusterId=cluster_id)["Steps"]
    assert len(steps) == 1, f"expected exactly the one submitted step, got {steps!r}"
    step_id = steps[0]["Id"]

    final = _poll(
        lambda: _step_state(emr, cluster_id, step_id),
        lambda s: s in TERMINAL_STEP_STATES,
        timeout_s=1800,
        interval_s=30,
        description=f"step {step_id} reaches a terminal state",
    )
    described = emr.describe_step(ClusterId=cluster_id, StepId=step_id)["Step"]
    assert final == "COMPLETED", (
        f"step ended {final!r}, expected COMPLETED "
        f"(FailureDetails: {described['Status'].get('FailureDetails')!r})"
    )

    # A COMPLETED step must have a real, ordered execution window.
    timeline = described["Status"]["Timeline"]
    for field in ("CreationDateTime", "StartDateTime", "EndDateTime"):
        assert field in timeline, (
            f"a COMPLETED step must carry Status.Timeline.{field}, got {timeline!r}"
        )
    assert timeline["CreationDateTime"] <= timeline["StartDateTime"] <= timeline["EndDateTime"], (
        f"step timeline must be ordered creation <= start <= end, got {timeline!r}"
    )

    # THE assertion: the artifact actually ran and produced these exact bytes.
    def _get_object():
        try:
            return s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("NoSuchKey", "404"):
                return None
            raise

    body = _poll(
        _get_object,
        lambda b: b is not None,
        timeout_s=120,
        interval_s=5,
        description=f"s3://{bucket}/{key} written by the completed step",
    )
    assert body.decode("utf-8") == nonce, (
        f"the step's output object must contain exactly the nonce it was given; "
        f"expected {nonce!r}, got {body!r}"
    )

    # And EMR must have shipped the step's own logs to LogUri — a status-flipping
    # emulator produces no log prefix at all.
    log_prefix = f"logs/{cluster_id}/steps/{step_id}/"
    listed = _poll(
        lambda: s3.list_objects_v2(Bucket=bucket, Prefix=log_prefix).get("KeyCount", 0),
        lambda n: n > 0,
        timeout_s=300,
        interval_s=15,
        description=f"step logs published under s3://{bucket}/{log_prefix}",
    )
    assert listed > 0, f"no step logs under s3://{bucket}/{log_prefix}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
