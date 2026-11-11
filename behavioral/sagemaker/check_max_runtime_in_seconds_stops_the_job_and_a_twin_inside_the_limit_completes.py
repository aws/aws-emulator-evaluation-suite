"""max-runtime-in-seconds-stops-the-job-and-a-twin-inside-the-limit-completes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "max-runtime-in-seconds-stops-the-job-and-a-twin-inside-the-limit-completes"
GROUP = "server-side"
SERVICES = ["sagemaker"]

#: The cap both jobs declare: small enough to observe, large enough that the control's
#: provisioning, built-in-image pull and container start on ml.m5.large — well over a minute by
#: itself — cannot accidentally exceed it together with its own sleep.
_MAX_RUNTIME_S = 300
#: Seconds the overrun job may spend terminating past the cap: the documented 120 s SIGTERM delay
#: plus headroom for model artifact upload.
_SIGTERM_GRACE_S = 300
#: Runtime of the twin control, far inside the cap.
_CONTROL_SLEEP_S = 5
#: Runtime the overrun job asks for. An order of magnitude past the cap, so "it was stopped by the
#: cap" and "it happened to finish" cannot be confused.
_OVERRUN_SLEEP_S = 1800

_MARKER = "MaxRuntimeExceeded"


# timing:real-time — workflow: 300 s https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_StoppingCondition.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """MaxRuntimeInSeconds is enforced: of two jobs under the same cap, the overrun one is ended
    (Stopped/Failed), attributed MaxRuntimeExceeded and bounded two-sided by the cap, while its
    twin inside the cap reaches Completed."""
    sm = ctx.client("sagemaker")
    bucket = _create_scratch_bucket(ctx)
    role_arn = _create_exec_role(ctx, bucket)

    # Started back-to-back so both provision in the same window; the twin separates "the cap
    # fired" from "no training job can run here" and from "everything is stopped".
    overrun_job = _start_sleep_job(ctx, role_arn, bucket, _OVERRUN_SLEEP_S, "overrun")
    control_job = _start_sleep_job(ctx, role_arn, bucket, _CONTROL_SLEEP_S, "control")

    # One shared deadline: the jobs run concurrently, so per-job deadlines would double the
    # worst case.
    overrun_seen: set[str] = set()
    control_seen: set[str] = set()
    shared_deadline = _deadline(ctx, _JOB_TIMEOUT_S)
    overrun = _poll_terminal(sm, overrun_job, overrun_seen, shared_deadline)
    control = _poll_terminal(sm, control_job, control_seen, shared_deadline)

    assert control["TrainingJobStatus"] == "Completed", (
        f"the twin control ({_CONTROL_SLEEP_S}s, cap {_MAX_RUNTIME_S}s) must complete untouched: "
        f"expected TrainingJobStatus='Completed', got {control['TrainingJobStatus']!r}; "
        f"FailureReason={control.get('FailureReason')!r}, SecondaryStatus="
        f"{control['SecondaryStatus']!r}"
    )
    control_elapsed = (control["TrainingEndTime"] - control["TrainingStartTime"]).total_seconds()
    assert control_elapsed < _MAX_RUNTIME_S, (
        f"the control must finish strictly inside the cap, proving the cap was never the reason "
        f"anything ended: expected < {_MAX_RUNTIME_S}s, measured {control_elapsed:.1f}s"
    )
    assert _MARKER not in _attribution_surfaces(control, control_seen), (
        f"the control must NOT be attributed to the runtime cap: {_MARKER!r} appeared in "
        f"{sorted(_attribution_surfaces(control, control_seen))}"
    )

    assert overrun["TrainingJobStatus"] != "Completed", (
        f"a job asking for {_OVERRUN_SLEEP_S}s under a {_MAX_RUNTIME_S}s cap must not complete: "
        f"got TrainingJobStatus='Completed', SecondaryStatus={overrun['SecondaryStatus']!r}"
    )
    assert overrun["TrainingJobStatus"] in ("Stopped", "Failed"), (
        f"the overrun job must be ENDED by SageMaker: expected TrainingJobStatus in "
        f"('Stopped', 'Failed'), got {overrun['TrainingJobStatus']!r}; "
        f"FailureReason={overrun.get('FailureReason')!r}"
    )

    # MaxRuntimeExceeded is a SecondaryStatus enum value; it may appear in the terminal status,
    # the transitions trail, or FailureReason.
    surfaces = _attribution_surfaces(overrun, overrun_seen)
    assert _MARKER in surfaces, (
        f"the overrun must be attributed to the runtime cap: expected {_MARKER!r} in the terminal "
        f"SecondaryStatus, the SecondaryStatusTransitions trail, or FailureReason; observed "
        f"surfaces {sorted(surfaces)} (status {overrun['TrainingJobStatus']!r}, FailureReason "
        f"{overrun.get('FailureReason')!r})"
    )

    # The docs do not say which clock starts the window: the lower bound uses CreationTime and
    # the upper bound TrainingStartTime, so the pair holds either way.
    end = overrun["TrainingEndTime"]
    total_elapsed = (end - overrun["CreationTime"]).total_seconds()
    training_elapsed = (end - overrun["TrainingStartTime"]).total_seconds()
    assert total_elapsed >= _MAX_RUNTIME_S, (
        f"the overrun job must actually be granted its allotted runtime before being ended: "
        f"expected TrainingEndTime - CreationTime >= {_MAX_RUNTIME_S}s, measured "
        f"{total_elapsed:.1f}s (a target that ends the job immediately fails here)"
    )
    assert training_elapsed <= _MAX_RUNTIME_S + _SIGTERM_GRACE_S, (
        f"the cap must actually cap: expected TrainingEndTime - TrainingStartTime <= "
        f"{_MAX_RUNTIME_S + _SIGTERM_GRACE_S}s ({_MAX_RUNTIME_S}s cap + {_SIGTERM_GRACE_S}s "
        f"documented SIGTERM/upload grace), measured {training_elapsed:.1f}s of a "
        f"{_OVERRUN_SLEEP_S}s request"
    )

    listed = _list_pair(sm, overrun_job, control_job)
    assert listed[overrun_job] == overrun["TrainingJobStatus"], (
        f"ListTrainingJobs must agree with DescribeTrainingJob for the overrun job: list says "
        f"{listed[overrun_job]!r}, describe says {overrun['TrainingJobStatus']!r}"
    )
    assert listed[control_job] == "Completed", (
        f"ListTrainingJobs must show the control as Completed: got {listed[control_job]!r}"
    )
    assert listed[overrun_job] != listed[control_job], (
        f"the two jobs differ ONLY in requested runtime, so their terminal statuses must differ; "
        f"both are {listed[control_job]!r}"
    )
    for name, desc in ((overrun_job, overrun), (control_job, control)):
        echoed = desc["StoppingCondition"]["MaxRuntimeInSeconds"]
        assert echoed == _MAX_RUNTIME_S, (
            f"{name} must echo the cap it was created with: expected MaxRuntimeInSeconds="
            f"{_MAX_RUNTIME_S}, got {echoed}"
        )


import json  # noqa: E402
import time  # noqa: E402

from botocore.exceptions import ClientError  # noqa: E402

#: Covers both jobs, which run concurrently.
_JOB_TIMEOUT_S = 900.0
#: Bounded window for IAM role propagation to SageMaker.
_IAM_PROPAGATION_TIMEOUT_S = 120.0
#: CreateTrainingJob rejects images outside a caller-visible ECR repo (even public.ecr.aws) with
#: "TrainingImageConfig with TrainingRepositoryAccessMode set to VPC must be provided ...";
#: the built-in XGBoost image in its AWS-owned per-region repo is exempt. Unknown regions raise.
_XGBOOST_REGISTRY_BY_REGION = {
    "us-east-1": "683313688378",
    "us-east-2": "257758044811",
    "us-west-1": "746614075791",
    "us-west-2": "246618743249",
    "eu-west-1": "685385470294",
    "eu-central-1": "813361260812",
    "ap-southeast-1": "121021644041",
    "ap-southeast-2": "783357654285",
    "ap-northeast-1": "501404015308",
    "ap-south-1": "720646828776",
}


def _deadline(ctx, timeout_s: float) -> float:
    """Monotonic deadline ``timeout_s`` ahead, capped by the run's remaining time."""
    left = ctx.time_left()
    return time.monotonic() + (timeout_s if left is None else max(1.0, min(timeout_s, left - 10.0)))


def _create_exec_role(ctx, bucket: str) -> str:
    """Create the execution role. AmazonSageMakerFullAccess only grants S3 on `sagemaker*`-like
    bucket names, so an inline policy scoped to this check's bucket lets artifact upload succeed."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-smmr-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sagemaker.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    scratch_policy_name = "sim2real-smmr-scratch-bucket"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=scratch_policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=scratch_policy_name))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_scratch_bucket(ctx) -> str:
    """Create (or adopt) the OutputDataConfig bucket."""
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name(f"sim2real-smmr-{account}-").lower()
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    try:
        s3.create_bucket(**kwargs)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            raise
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=name)


def _start_sleep_job(ctx, role_arn: str, bucket: str, sleep_s: int, label: str) -> str:
    """Start a training job that only sleeps, retrying within the IAM-propagation window."""
    sm = ctx.client("sagemaker")
    job_name = ctx.unique_name(f"sim2real-smmr-{label}-")
    registry_id = _XGBOOST_REGISTRY_BY_REGION.get(ctx.region)
    if registry_id is None:
        raise AssertionError(f"no known built-in XGBoost algorithm registry ID for region {ctx.region!r}")
    training_image = f"{registry_id}.dkr.ecr.{ctx.region}.amazonaws.com/sagemaker-xgboost:1.7-1"
    params = {
        "TrainingJobName": job_name,
        "RoleArn": role_arn,
        "AlgorithmSpecification": {
            "TrainingImage": training_image,
            "TrainingInputMode": "File",
            "ContainerEntrypoint": ["/bin/sh", "-c"],
            "ContainerArguments": [f"sleep {sleep_s}"],
        },
        "OutputDataConfig": {"S3OutputPath": f"s3://{bucket}/{label}/"},
        "ResourceConfig": {
            "InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5
        },
        "StoppingCondition": {"MaxRuntimeInSeconds": _MAX_RUNTIME_S},
        "Tags": [{"Key": "sim2real-check", "Value": CHECK}],
    }
    deadline = _deadline(ctx, _IAM_PROPAGATION_TIMEOUT_S)
    while True:
        try:
            sm.create_training_job(**params)
            break
        except ClientError as exc:
            msg = str(exc)
            transient = (
                "AccessDenied" in msg
                or "cannot be assumed" in msg
                or "Could not assume role" in msg
                or "not authorized" in msg
            )
            if not transient or time.monotonic() >= deadline:
                raise AssertionError(
                    f"CreateTrainingJob({label}) did not succeed within "
                    f"{_IAM_PROPAGATION_TIMEOUT_S}s of role creation; last error: {exc}"
                ) from exc
            time.sleep(2)
    ctx.on_cleanup(lambda: _stop_if_running(ctx, job_name))
    return job_name


def _stop_if_running(ctx, job_name: str) -> None:
    """Stop this check's own job if it is still running."""
    sm = ctx.client("sagemaker")
    try:
        status = sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise
        return
    if status == "InProgress":
        sm.stop_training_job(TrainingJobName=job_name)


def _poll_terminal(sm, job_name: str, seen: set[str], deadline: float) -> dict:
    """Poll to a terminal TrainingJobStatus, adding every SecondaryStatus observed into *seen*
    (transient states cannot be read back later). Raises on timeout."""
    last = None
    while time.monotonic() < deadline:
        last = sm.describe_training_job(TrainingJobName=job_name)
        secondary = last.get("SecondaryStatus")
        if secondary:
            seen.add(secondary)
        if last["TrainingJobStatus"] in ("Completed", "Failed", "Stopped"):
            return last
        time.sleep(2)
    raise AssertionError(
        f"training job {job_name} did not reach a terminal status within the shared "
        f"{_JOB_TIMEOUT_S}s budget; last "
        f"status {last['TrainingJobStatus'] if last else 'unknown'}, secondary statuses seen "
        f"{sorted(seen)}"
    )


def _attribution_surfaces(desc: dict, seen: set[str]) -> set[str]:
    """Tokens from every place SageMaker could name the cause: polled secondary statuses, the
    SecondaryStatusTransitions trail, and FailureReason."""
    surfaces = set(seen)
    surfaces.add(desc["SecondaryStatus"])
    for t in desc.get("SecondaryStatusTransitions", []):
        surfaces.add(t["Status"])
    reason = desc.get("FailureReason") or ""
    if _MARKER in reason:
        surfaces.add(_MARKER)
    return surfaces


def _list_pair(sm, *job_names: str) -> dict:
    """Map job name to TrainingJobStatus via ListTrainingJobs, an independent read."""
    found: dict = {}
    for name in job_names:
        page = sm.list_training_jobs(NameContains=name, MaxResults=10)
        matches = [
            s for s in page["TrainingJobSummaries"] if s["TrainingJobName"] == name
        ]
        assert len(matches) == 1, (
            f"ListTrainingJobs(NameContains={name!r}) must return exactly the one job this check "
            f"created, got {[s['TrainingJobName'] for s in page['TrainingJobSummaries']]}"
        )
        found[name] = matches[0]["TrainingJobStatus"]
    return found


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
