"""braket-search-jobs-and-quantum-tasks-no-match-returns-empty-list."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "braket-search-jobs-and-quantum-tasks-no-match-returns-empty-list"
GROUP = "data-plane"
SERVICES = ["braket"]

SV1_ARN = "arn:aws:braket:::device/quantum-simulator/amazon/sv1"
PUBLIC_IMAGE = "public.ecr.aws/docker/library/busybox:latest"
BELL_ACTION = json.dumps(
    {
        "braketSchemaHeader": {"name": "braket.ir.openqasm.program", "version": "1"},
        "source": (
            "OPENQASM 3.0; bit[2] b; qubit[2] q; h q[0]; cnot q[0], q[1]; "
            "b[0] = measure q[0]; b[1] = measure q[1];"
        ),
    }
)


@tags("axis:happy-path", "cap:c2", "concern:representation", "dp:native", "plane:control", "plane:data")
def run(ctx) -> None:
    """SearchJobs/SearchQuantumTasks filtered by a valid but never-issued ARN return an empty list
    (200), unlike Get* which raise ResourceNotFoundException; each search first finds a real
    task/job so an always-empty answer cannot pass."""
    require_tools("docker", "aws")
    braket = ctx.client("braket")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region
    ghost = ctx.unique_name("sim2real-ghost-")

    # CreateQuantumTask (like CreateJob below) needs AWSServiceRoleForAmazonBraket to exist in
    # the account; on a fresh account that has never used Braket it does not, and the call fails
    # with AccessDeniedException rather than creating the role implicitly (empirically confirmed
    # against real AWS -- this is not documented as a CreateJob-only requirement).
    _ensure_braket_service_linked_role(ctx)
    bucket = _create_output_bucket(ctx)

    # Positive control: search_quantum_tasks must find a task that really exists.
    task_arn = _create_quantum_task(ctx, braket, bucket)
    found_tasks = _poll_until(
        lambda: braket.search_quantum_tasks(
            filters=[{"name": "quantumTaskArn", "values": [task_arn], "operator": "EQUAL"}]
        )["quantumTasks"],
        lambda found: len(found) == 1,
        timeout_s=30,
        interval_s=2,
    )
    assert found_tasks[0]["quantumTaskArn"] == task_arn, (
        f"expected search to return the just-created task {task_arn!r}, got {found_tasks!r}"
    )
    _best_effort_cancel_task(ctx, braket, task_arn)

    # Positive control: search_jobs must find a job that really exists. CreateJob validates
    # role assumability and container-image existence eagerly, so the positive control needs a
    # real assumable role and a real pushed image (empirically confirmed against real AWS).
    role_arn = _create_assumable_role(ctx, bucket)
    image_uri = _push_real_image(ctx)
    job_arn = _create_job_past_role_propagation(
        braket,
        {
            "clientToken": ctx.unique_name("sim2real-search-job-tok-"),
            "jobName": ctx.unique_name("sim2real-search-job-"),
            "roleArn": role_arn,
            "algorithmSpecification": {"containerImage": {"uri": image_uri}},
            "outputDataConfig": {"s3Path": f"s3://{bucket}/output"},
            "instanceConfig": {"instanceType": "ml.m5.large", "volumeSizeInGb": 30},
            "deviceConfig": {"device": SV1_ARN},
            "tags": {"sim2real": CHECK},
        },
    )
    ctx.on_cleanup(lambda: _best_effort_cancel_job(braket, job_arn))
    found_jobs = _poll_until(
        lambda: braket.search_jobs(
            filters=[{"name": "jobArn", "values": [job_arn], "operator": "EQUAL"}]
        )["jobs"],
        lambda found: len(found) == 1,
        timeout_s=30,
        interval_s=2,
    )
    assert found_jobs[0]["jobArn"] == job_arn, (
        f"expected search to return the just-created job {job_arn!r}, got {found_jobs!r}"
    )
    braket.cancel_job(jobArn=job_arn)

    # The negative this check exists for: a syntactically valid but never-issued ARN matches
    # nothing, and does so as a 200 with an empty list rather than a ResourceNotFoundException.
    fake_job = f"arn:aws:braket:{region}:{account_id}:job/{ghost}"
    fake_task = f"arn:aws:braket:{region}:{account_id}:quantum-task/{ghost}"

    jobs = braket.search_jobs(
        filters=[{"name": "jobArn", "values": [fake_job], "operator": "EQUAL"}]
    )["jobs"]
    assert jobs == [], f"expected no jobs to match a nonexistent jobArn, got {jobs!r}"

    tasks = braket.search_quantum_tasks(
        filters=[{"name": "quantumTaskArn", "values": [fake_task], "operator": "EQUAL"}]
    )["quantumTasks"]
    assert tasks == [], f"expected no tasks to match a nonexistent quantumTaskArn, got {tasks!r}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _create_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    # AWSServiceRoleForAmazonBraket's own policy only grants access to buckets named
    # "amazon-braket-*" -- CreateQuantumTask has no roleArn of its own to carry broader S3
    # permissions, so the output bucket must use that prefix (empirically confirmed against
    # real AWS: a differently-prefixed bucket fails with "Caller doesn't have access to bucket").
    name = ctx.unique_name("amazon-braket-sim2real-search-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_quantum_task(ctx, braket, bucket: str, *, timeout_s: float = 60.0) -> str:
    # A service-linked role just created via CreateServiceLinkedRole is not immediately usable
    # by CreateQuantumTask -- the same IAM propagation lag CreateJob's own retry loop works
    # around below (empirically confirmed against real AWS).
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            resp = braket.create_quantum_task(
                clientToken=ctx.unique_name("sim2real-search-task-"),
                deviceArn=SV1_ARN,
                action=BELL_ACTION,
                shots=10,
                outputS3Bucket=bucket,
                outputS3KeyPrefix="results",
                tags={"sim2real": CHECK},
            )
            break
        except ClientError as exc:
            transient = (
                exc.response["Error"]["Code"] == "AccessDeniedException"
                and "role doesn't exist" in str(exc).lower()
            )
            if transient and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    task_arn = resp["quantumTaskArn"]
    ctx.on_cleanup(lambda: _best_effort_cancel_task(ctx, braket, task_arn))
    return task_arn


_STOPPED = ("CANCELLING", "CANCELLED", "COMPLETED", "FAILED")


def _cancel_unless_stopped(cancel, read_status) -> None:
    """Cancel; ResourceNotFoundException, or ConflictException on an already stopped resource,
    is fine; any other failure raises."""
    try:
        cancel()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "ResourceNotFoundException":
            return
        if code != "ConflictException" or read_status() not in _STOPPED:
            raise


def _best_effort_cancel_task(ctx, braket, task_arn: str) -> None:
    _cancel_unless_stopped(
        lambda: braket.cancel_quantum_task(
            quantumTaskArn=task_arn, clientToken=ctx.unique_name("sim2real-cleanup-cancel-")
        ),
        lambda: braket.get_quantum_task(quantumTaskArn=task_arn)["status"],
    )


def _best_effort_cancel_job(braket, job_arn: str) -> None:
    _cancel_unless_stopped(
        lambda: braket.cancel_job(jobArn=job_arn),
        lambda: braket.get_job(jobArn=job_arn)["status"],
    )


def _ensure_braket_service_linked_role(ctx) -> None:
    """CreateJob needs AWSServiceRoleForAmazonBraket to exist in the account; on a fresh
    account that has never used Braket Jobs it does not, and CreateJob fails with
    AccessDeniedException (empirically confirmed) rather than creating it implicitly."""
    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="braket.amazonaws.com")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInput":
            raise


def _create_assumable_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-braket-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "braket.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonBraketFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    inline_policy_name = ctx.unique_name("sim2real-braket-inline-")
    inline_policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ecr:GetAuthorizationToken",
                    "ecr:BatchCheckLayerAvailability",
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:BatchGetImage",
                ],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket"],
                "Resource": f"arn:aws:s3:::{bucket}",
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": f"arn:aws:s3:::{bucket}/*",
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=inline_policy_name, PolicyDocument=json.dumps(inline_policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=inline_policy_name))
    return role["Role"]["Arn"]


def _push_real_image(ctx) -> str:
    """Create a private ECR repo and push a real, pullable public image into it -- CreateJob
    resolves the referenced image eagerly (empirically confirmed), so the positive control needs
    an image that genuinely exists, not just a repo."""
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-braket-search-repo-")
    repo = ecr.create_repository(repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}])["repository"]
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    repo_uri = repo["repositoryUri"]
    registry = repo_uri.split("/")[0]
    image_ref = f"{repo_uri}:latest"

    _run_script(
        ctx,
        f"""
        aws ecr get-login-password --region {ctx.region} \\
            | docker login --username AWS --password-stdin {registry}
        docker pull {PUBLIC_IMAGE}
        docker tag {PUBLIC_IMAGE} {image_ref}
        docker push {image_ref}
        """,
        timeout_s=300,
    )
    return image_ref


def _run_shell(ctx, command, *, timeout_s=60.0, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"command failed (rc={result.returncode}):\n  cmd: {command}\n  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_script(ctx, script: str, *, timeout_s=120.0):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
        f.write("#!/bin/bash\nset -euo pipefail\n")
        f.write(script)
        script_path = f.name
    try:
        os.chmod(script_path, 0o755)
        return _run_shell(ctx, ["bash", script_path], timeout_s=timeout_s)
    finally:
        os.unlink(script_path)


def _create_job_past_role_propagation(braket, request: dict, *, timeout_s=90.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return braket.create_job(**request)["jobArn"]
        except ClientError as exc:
            msg = str(exc).lower()
            transient = (
                "cannot assume" in msg or "cannot find container image" in msg or "cannot list the s3" in msg
            )
            if exc.response["Error"]["Code"] == "ValidationException" and transient:
                if time.monotonic() >= deadline:
                    raise AssertionError("create_job never succeeded (IAM/ECR propagation timeout)") from exc
                time.sleep(3)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
