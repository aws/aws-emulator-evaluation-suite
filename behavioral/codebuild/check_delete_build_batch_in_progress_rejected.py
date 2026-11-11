"""delete-build-batch-in-progress-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "delete-build-batch-in-progress-rejected"
GROUP = "state-machine"
SERVICES = ["codebuild"]

# The leg outlasts the check, so the batch is IN_PROGRESS until StopBuildBatch ends it.
_BUILDSPEC = """version: 0.2
batch:
  fast-fail: false
  build-list:
    - identifier: build1
phases:
  build:
    commands:
      - sleep 900
"""


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteBuildBatch on a still-IN_PROGRESS batch is rejected, the batch build is left
    intact, and the same batch can be deleted normally once actually stopped (positive control)."""
    codebuild = ctx.client("codebuild")
    role_arn = _create_codebuild_role(ctx)
    project_name = ctx.unique_name("sim2real-cbbatchneg-")
    _create_project_with_retry(
        codebuild,
        name=project_name,
        source={"type": "NO_SOURCE", "buildspec": _BUILDSPEC},
        artifacts={"type": "NO_ARTIFACTS"},
        environment={
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
            "computeType": "BUILD_GENERAL1_SMALL",
        },
        serviceRole=role_arn,
        buildBatchConfig={"serviceRole": role_arn, "combineArtifacts": False},
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: codebuild.delete_project(name=project_name))

    batch_id = codebuild.start_build_batch(projectName=project_name)["buildBatch"]["id"]
    ctx.on_cleanup(lambda: _safe_delete_batch(codebuild, batch_id))

    def batch_info():
        got = codebuild.batch_get_build_batches(ids=[batch_id])["buildBatches"]
        return got[0] if got else None

    def batch_status():
        info = batch_info()
        return info["buildBatchStatus"] if info else None

    status = _poll_until(batch_status, lambda s: s is not None, timeout_s=60, interval_s=3)
    assert status == "IN_PROGRESS", f"expected freshly started batch to be IN_PROGRESS, got {status}"

    # --- break exactly one thing: delete while still in progress ---
    code, message = _error_code(lambda: codebuild.delete_build_batch(id=batch_id))
    assert code == "InvalidInputException", f"expected InvalidInputException, got {code}"
    assert message == f"Cannot delete BuildBatch arn:aws:codebuild:{ctx.region}:{ctx.account}:build-batch/{batch_id}, as it is still in progress", (
        f"expected the exact InvalidInputException message AWS returns, got {message!r}"
    )

    # effect absent: the batch build still exists and is still IN_PROGRESS
    still_there = codebuild.batch_get_build_batches(ids=[batch_id])["buildBatches"]
    assert len(still_there) == 1, "batch build vanished after a rejected DeleteBuildBatch call"
    still_status = still_there[0]["buildBatchStatus"]
    assert still_status == "IN_PROGRESS", f"expected batch to remain IN_PROGRESS, got {still_status}"
    listed_ids = codebuild.list_build_batches().get("ids", [])
    assert batch_id in listed_ids, f"expected {batch_id} in ListBuildBatches ids, got {listed_ids}"

    # --- positive control: the same batch build CAN be deleted once actually stopped ---
    codebuild.stop_build_batch(id=batch_id)
    _poll_until(batch_status, lambda s: s == "STOPPED", timeout_s=300, interval_s=10)
    # The buildBatchStatus flips to STOPPED before the batch is fully "complete" and
    # deletable; wait for the complete flag too, retrying on the transient InvalidInputException.
    _poll_until(lambda: bool((batch_info() or {}).get("complete")), lambda c: c, timeout_s=120, interval_s=5)

    def _try_delete():
        try:
            codebuild.delete_build_batch(id=batch_id)
            return True
        except codebuild.exceptions.InvalidInputException:
            return False

    _poll_until(_try_delete, lambda deleted: deleted, timeout_s=120, interval_s=5)
    _poll_until(
        lambda: batch_id not in codebuild.list_build_batches().get("ids", []),
        lambda absent: absent,
        timeout_s=30,
        interval_s=2,
    )


# ===== helpers =====


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _error_code(fn):
    """Return the ClientError code and message fn() raises. An unexpected SUCCESS raises directly,
    so an over-permissive target fails here rather than passing a code comparison by coincidence."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_codebuild_role(ctx, extra_statements=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cb-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codebuild.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    managed_policy_arn = "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn))
    if extra_statements:
        policy_name = f"{role_name}-extra"
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": extra_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_project_with_retry(codebuild, timeout_s=90.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return codebuild.create_project(**kwargs)["project"]
        except codebuild.exceptions.InvalidInputException as exc:
            last_exc = exc
            time.sleep(5)
    raise last_exc


def _safe_delete_batch(codebuild, batch_id):
    """Teardown: returns once the batch is gone; stops a running batch and retries the delete
    while CodeBuild still reports it in progress, then raises."""
    from botocore.exceptions import ClientError

    batches = codebuild.batch_get_build_batches(ids=[batch_id])["buildBatches"]
    if not batches:
        return
    if batches[0]["buildBatchStatus"] == "IN_PROGRESS":
        codebuild.stop_build_batch(id=batch_id)
    deadline = time.monotonic() + 300.0
    while True:
        try:
            codebuild.delete_build_batch(id=batch_id)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidInputException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
