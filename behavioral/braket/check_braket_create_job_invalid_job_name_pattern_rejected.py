"""braket-create-job-invalid-job-name-pattern-rejected."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "braket-create-job-invalid-job-name-pattern-rejected"
GROUP = "error-semantics"
SERVICES = ["braket"]

SV1_ARN = "arn:aws:braket:::device/quantum-simulator/amazon/sv1"
PUBLIC_IMAGE = "public.ecr.aws/docker/library/busybox:latest"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:native", "plane:control", "plane:data")
def run(ctx) -> None:
    """CreateJob rejects a jobName that violates the documented naming pattern, while the request with a
    pattern-valid jobName, a real assumable role and a pushed image is accepted, so the refusal is
    about the name."""
    require_tools("docker", "aws")
    braket = ctx.client("braket")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region

    def _request(job_name: str, client_token: str) -> dict:
        return {
            "clientToken": client_token,
            "jobName": job_name,
            "roleArn": f"arn:aws:iam::{account_id}:role/sim2real-nonexistent-braket-role",
            "algorithmSpecification": {
                "containerImage": {
                    "uri": f"{account_id}.dkr.ecr.{region}.amazonaws.com/sim2real-nonexistent-repo:latest"
                }
            },
            "outputDataConfig": {"s3Path": f"s3://sim2real-nonexistent-bucket-{account_id}/output"},
            "instanceConfig": {"instanceType": "ml.m5.large", "volumeSizeInGb": 30},
            "deviceConfig": {"device": SV1_ARN},
            "tags": {"sim2real": CHECK},
        }

    bad_request = _request("bad_job_name!", ctx.unique_name("sim2real-badjob-"))
    # underscore/exclamation violate ^[a-zA-Z0-9](-*[a-zA-Z0-9]){0,50}$
    err = _client_error(lambda: braket.create_job(**bad_request))
    # Real AWS reports a malformed jobName via the generic BadRequestException, not
    # ValidationException (empirically verified against the live Braket control plane).
    assert err["Code"] == "BadRequestException", f"expected BadRequestException, got {err!r}"
    assert err["Message"] == "Invalid request body", (
        f"expected message 'Invalid request body', got {err['Message']!r}"
    )

    # Positive control: the identical request, with only jobName made pattern-valid, is
    # accepted -- proving the rejection above is attributable to jobName alone, and not to the
    # role/image/bucket every request here starts out sharing (fabricated in the rejected call,
    # made real below so the accepted call has nothing else left to fail on).
    _ensure_braket_service_linked_role(ctx)
    bucket = _create_output_bucket(ctx)
    role_arn = _create_assumable_role(ctx, bucket)
    image_uri = _push_real_image(ctx)
    good_job_name = ctx.unique_name("sim2real-goodjob-")
    good_request = _request(good_job_name, ctx.unique_name("sim2real-goodjob-tok-"))
    good_request["roleArn"] = role_arn
    good_request["algorithmSpecification"]["containerImage"]["uri"] = image_uri
    good_request["outputDataConfig"] = {"s3Path": f"s3://{bucket}/output"}
    job_arn = _create_job_past_role_propagation(braket, good_request)
    ctx.on_cleanup(lambda: _best_effort_cancel(ctx, braket, job_arn))

    # Cancel immediately: the point is that CreateJob accepted the request, not that the job
    # (which references a nonexistent role) runs to completion.
    braket.cancel_job(jobArn=job_arn)
    terminal = _poll_until(
        lambda: braket.get_job(jobArn=job_arn)["status"],
        lambda status: status in ("CANCELLED", "FAILED", "COMPLETED"),
        timeout_s=120,
        interval_s=3,
    )
    assert terminal in ("CANCELLED", "FAILED"), f"job {job_arn} ended in unexpected status {terminal!r}"


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


_TERMINAL = ("CANCELLED", "FAILED", "COMPLETED")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _best_effort_cancel(ctx, braket, job_arn) -> None:
    """Cancel the job unless it is gone or already terminal; CancelJob answers ConflictException
    for a job that already reached a terminal status."""
    try:
        braket.cancel_job(jobArn=job_arn)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "ResourceNotFoundException":
            return
        if code == "ConflictException" and braket.get_job(jobArn=job_arn)["status"] in _TERMINAL:
            return
        raise


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


def _create_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-braket-out-").lower()
    if ctx.region == "us-east-1":  # S3 CreateBucket rejects LocationConstraint for this one region
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
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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
    name = ctx.unique_name("sim2real-braket-repo-")
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
            # A just-created role reads as unable to reach the device until IAM propagates it.
            transient = (
                "cannot assume" in msg or "cannot find container image" in msg or "cannot list the s3" in msg
                or "not found with the provided iam role" in msg
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
