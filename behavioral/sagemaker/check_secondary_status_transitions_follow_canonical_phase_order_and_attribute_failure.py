"""secondary-status-transitions-follow-canonical-phase-order-and-attribute-failure."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "secondary-status-transitions-follow-canonical-phase-order-and-attribute-failure"
GROUP = "ordering"
SERVICES = ["sagemaker"]

#: The non-terminal lifecycle phases in the order the SecondaryStatus enum declares them. A job need
#: not visit all of them; those it does visit must appear in this relative order, each at most once.
_CANONICAL = (
    "Starting",
    "LaunchingMLInstances",
    "PreparingTrainingStack",
    "Downloading",
    "DownloadingTrainingImage",
    "Training",
    "Uploading",
)
#: Terminal secondary statuses. A transition list must end in exactly one of these.
_TERMINALS = frozenset({"Completed", "Failed", "Stopped", "MaxRuntimeExceeded", "Interrupted"})
#: How long each container works before exiting, so the Training phase is genuinely entered.
_WORK_SLEEP_S = 20
#: The non-zero exit code the failing twin uses; distinctive so it is recognizable in FailureReason.
_FAIL_EXIT_CODE = 7
#: Generous enough that the runtime cap is never the reason either job ends.
_MAX_RUNTIME_S = 600
#: CreateTrainingJob rejects images outside a caller-visible ECR repo (even public.ecr.aws) with
#: "TrainingImageConfig with TrainingRepositoryAccessMode set to VPC must be provided ...";
#: the built-in XGBoost image in its AWS-owned per-region repo is exempt.
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


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """For two training jobs differing only in exit code, SecondaryStatusTransitions lists visited
    phases in canonical order without repeats, ends Failed vs Completed per the exit code, and only
    the failing twin carries a FailureReason."""
    sm = ctx.client("sagemaker")
    role_arn = _create_exec_role(ctx)
    bucket = _create_scratch_bucket(ctx)

    # Two jobs differing only in the container's exit code.
    fail_job = _start_job(ctx, role_arn, bucket, f"sleep {_WORK_SLEEP_S}; exit {_FAIL_EXIT_CODE}", "fail")
    pass_job = _start_job(ctx, role_arn, bucket, f"sleep {_WORK_SLEEP_S}", "pass")

    shared_deadline = time.monotonic() + _JOB_TIMEOUT_S
    failed = _poll_terminal(sm, fail_job, shared_deadline)
    passed = _poll_terminal(sm, pass_job, shared_deadline)

    assert passed["TrainingJobStatus"] == "Completed", (
        f"the zero-exit twin must complete: expected TrainingJobStatus='Completed', got "
        f"{passed['TrainingJobStatus']!r}; FailureReason={passed.get('FailureReason')!r}"
    )
    assert failed["TrainingJobStatus"] == "Failed", (
        f"the exit-{_FAIL_EXIT_CODE} twin must fail: expected TrainingJobStatus='Failed', got "
        f"{failed['TrainingJobStatus']!r}; FailureReason={failed.get('FailureReason')!r}"
    )

    for name, desc, expected_terminal in (
        (pass_job, passed, "Completed"),
        (fail_job, failed, "Failed"),
    ):
        transitions = desc["SecondaryStatusTransitions"]
        statuses = [t["Status"] for t in transitions]
        assert transitions, (
            f"{name}: a real training job must record its secondary phases; "
            f"SecondaryStatusTransitions is empty"
        )

        phases = [s for s in statuses if s in _CANONICAL]
        indices = [_CANONICAL.index(s) for s in phases]
        assert indices == sorted(set(indices)) and len(indices) == len(set(indices)), (
            f"{name}: visited phases must appear in canonical lifecycle order with no repeats: "
            f"got {phases} (canonical indices {indices}); canonical order is {list(_CANONICAL)}"
        )

        assert statuses[0] == "Starting", (
            f"{name}: the first secondary transition must be 'Starting', got {statuses[0]!r}; "
            f"full trail {statuses}"
        )
        assert statuses[-1] == expected_terminal, (
            f"{name}: the last secondary transition must be {expected_terminal!r}, got "
            f"{statuses[-1]!r}; full trail {statuses}"
        )
        terminal_positions = [i for i, s in enumerate(statuses) if s in _TERMINALS]
        assert terminal_positions == [len(statuses) - 1], (
            f"{name}: exactly one terminal secondary status, at the end: terminals found at "
            f"{terminal_positions} of {len(statuses)}; full trail {statuses}"
        )

        # Entering Training shows the outcome is the container's, not an image-pull failure.
        assert "Training" in statuses, (
            f"{name}: a container that ran for {_WORK_SLEEP_S}s must record the 'Training' phase; "
            f"trail {statuses}"
        )

        assert desc["SecondaryStatus"] == statuses[-1], (
            f"{name}: DescribeTrainingJob's SecondaryStatus must equal the last transition's "
            f"Status: SecondaryStatus={desc['SecondaryStatus']!r}, last transition "
            f"{statuses[-1]!r}"
        )

        starts = [t["StartTime"] for t in transitions]
        assert starts == sorted(starts), (
            f"{name}: transition StartTimes must be non-decreasing: "
            f"{[(s, t.isoformat()) for s, t in zip(statuses, starts)]}"
        )
        for t in transitions:
            if "EndTime" in t:
                assert t["EndTime"] >= t["StartTime"], (
                    f"{name}: transition {t['Status']!r} ends before it starts: "
                    f"{t['StartTime'].isoformat()} -> {t['EndTime'].isoformat()}"
                )
        assert desc["TrainingEndTime"] >= starts[-1], (
            f"{name}: TrainingEndTime {desc['TrainingEndTime'].isoformat()} precedes the last "
            f"transition's StartTime {starts[-1].isoformat()}"
        )

        unmessaged = [t["Status"] for t in transitions if not t.get("StatusMessage")]
        assert not unmessaged, (
            f"{name}: every secondary transition of a real job carries a StatusMessage; these do "
            f"not: {unmessaged}"
        )

    fail_reason = failed.get("FailureReason") or ""
    assert fail_reason.strip(), (
        f"a Failed training job must carry a non-empty FailureReason; got {fail_reason!r}. Its "
        f"trail was {[t['Status'] for t in failed['SecondaryStatusTransitions']]}"
    )
    pass_reason = passed.get("FailureReason") or ""
    assert not pass_reason.strip(), (
        f"a Completed training job must carry no FailureReason; got {pass_reason!r}"
    )
    fail_trail = [t["Status"] for t in failed["SecondaryStatusTransitions"]]
    pass_trail = [t["Status"] for t in passed["SecondaryStatusTransitions"]]
    assert fail_trail != pass_trail, (
        f"two jobs differing only in exit code must not produce identical phase trails; both are "
        f"{fail_trail}"
    )
    assert fail_trail[:-1] == [s for s in fail_trail[:-1] if s in _CANONICAL], (
        f"the failing job's trail must be canonical phases followed by exactly one terminal: "
        f"{fail_trail}"
    )

    listed = _list_pair(sm, fail_job, pass_job)
    assert listed[fail_job] == "Failed" and listed[pass_job] == "Completed", (
        f"ListTrainingJobs must report the divergence too: expected {{{fail_job}: 'Failed', "
        f"{pass_job}: 'Completed'}}, got {listed}"
    )


import json  # noqa: E402
import time  # noqa: E402

from botocore.exceptions import ClientError  # noqa: E402

#: Shared across both concurrent jobs.
_JOB_TIMEOUT_S = 600.0
#: Bounded window for IAM role propagation to SageMaker.
_IAM_PROPAGATION_TIMEOUT_S = 120.0


def _create_exec_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-smst-role-")
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
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_scratch_bucket(ctx) -> str:
    """Create (or adopt) the OutputDataConfig bucket."""
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name(f"sim2real-smst-{account}-").lower()
    kwargs = {"Bucket": name}
    # S3's CreateBucket rejects an explicit LocationConstraint of us-east-1.
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
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=name)


def _start_job(ctx, role_arn: str, bucket: str, shell: str, label: str) -> str:
    sm = ctx.client("sagemaker")
    job_name = ctx.unique_name(f"sim2real-smst-{label}-")
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
            "ContainerArguments": [shell],
        },
        "OutputDataConfig": {"S3OutputPath": f"s3://{bucket}/{label}/"},
        "ResourceConfig": {
            "InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5
        },
        "StoppingCondition": {"MaxRuntimeInSeconds": _MAX_RUNTIME_S},
        "Tags": [{"Key": "sim2real-check", "Value": CHECK}],
    }
    deadline = time.monotonic() + _IAM_PROPAGATION_TIMEOUT_S
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
            time.sleep(5)
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


def _poll_terminal(sm, job_name: str, deadline: float) -> dict:
    """Poll to a terminal TrainingJobStatus against a shared deadline (the jobs run concurrently,
    so per-job deadlines would double the worst case). Raises on timeout."""
    last = None
    while time.monotonic() < deadline:
        last = sm.describe_training_job(TrainingJobName=job_name)
        if last["TrainingJobStatus"] in ("Completed", "Failed", "Stopped"):
            return last
        time.sleep(2)
    raise AssertionError(
        f"training job {job_name} did not reach a terminal status within the shared "
        f"{_JOB_TIMEOUT_S}s budget; last status "
        f"{last['TrainingJobStatus'] if last else 'unknown'}, last secondary "
        f"{last.get('SecondaryStatus') if last else 'unknown'}"
    )


def _list_pair(sm, *job_names: str) -> dict:
    """Map job name to TrainingJobStatus via ListTrainingJobs, scoped by NameContains."""
    found: dict = {}
    for name in job_names:
        page = sm.list_training_jobs(NameContains=name, MaxResults=10)
        matches = [s for s in page["TrainingJobSummaries"] if s["TrainingJobName"] == name]
        assert len(matches) == 1, (
            f"ListTrainingJobs(NameContains={name!r}) must return exactly the one job this check "
            f"created, got {[s['TrainingJobName'] for s in page['TrainingJobSummaries']]}"
        )
        found[name] = matches[0]["TrainingJobStatus"]
    return found


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
