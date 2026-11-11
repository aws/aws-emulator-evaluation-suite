"""start-run-missing-workflow-not-found-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-run-missing-workflow-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["omics"]

_WDL_MAIN = """version 1.0

workflow sim2real_smoke {
  call hello
}

task hello {
  command {
    echo "hello from sim2real"
  }
  output {
    String message = read_string(stdout())
  }
  runtime {
    docker: "public.ecr.aws/amazonlinux/amazonlinux:2"
  }
}
"""


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartRun with a nonexistent workflowId fails with ResourceNotFoundException and the exact message
    and leaves no run, while a run on a real workflow starts and is listed."""
    omics = ctx.client("omics")
    bucket = _create_bucket(ctx)
    role_arn = _create_omics_trust_role(ctx, bucket)
    workflow_id = _create_workflow(ctx, omics)

    # positive control: a real workflowId is accepted and produces a run
    control_run_name = ctx.unique_name("sim2real-controlrun-")
    control = _retry_role_propagation(
        lambda: omics.start_run(
            workflowId=workflow_id,
            roleArn=role_arn,
            outputUri=f"s3://{bucket}/control-out/",
            requestId=ctx.unique_name("sim2real-controlreq-"),
            name=control_run_name,
        )
    )
    control_run_id = control["id"]
    ctx.on_cleanup(lambda: _cancel_run(omics, control_run_id))
    assert control_run_id, f"positive control did not return a run id: {control!r}"

    fake_workflow_id = "9999999999"
    run_name = ctx.unique_name("sim2real-run-")

    code, message = _error_code(
        lambda: omics.start_run(
            workflowId=fake_workflow_id,
            roleArn=role_arn,
            outputUri=f"s3://{bucket}/out/",
            requestId=ctx.unique_name("sim2real-runreq-"),
            name=run_name,
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == f"Workflow {fake_workflow_id} not found", f"unexpected not-found message: {message!r}"

    # terminal independent read, at the destination: the accepted control run is visible and the
    # rejected request left nothing behind
    control_names = {r.get("name") for r in omics.list_runs(name=control_run_name).get("items", [])}
    assert control_run_name in control_names, (
        f"positive-control run {control_run_name!r} is missing from ListRuns"
    )
    rejected = [r for r in omics.list_runs(name=run_name).get("items", []) if r.get("name") == run_name]
    assert rejected == [], f"a run named {run_name!r} exists despite the missing-workflow rejection"


def _retry_role_propagation(fn, timeout_s=60.0, interval_s=5.0):
    """Call ``fn``, retrying while a freshly created role has not propagated to Omics yet."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException") and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _error_code(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _cancel_run(omics, run_id) -> None:
    try:
        omics.cancel_run(id=run_id)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code not in ("ConflictException", "ResourceNotFoundException"):
            raise


def _delete_workflow(omics, workflow_id, timeout_s=300.0) -> None:
    # DeleteWorkflow answers ConflictException while a run of the workflow is still cancelling:
    # retry it every 2 s to the deadline, then raise.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            omics.delete_workflow(id=workflow_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _workflow_definition_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("main.wdl", _WDL_MAIN)
    return buf.getvalue()


def _create_workflow(ctx, omics) -> str:
    name = ctx.unique_name("sim2real-omics-startrun-wf-")
    created = omics.create_workflow(
        name=name,
        engine="WDL",
        definitionZip=_workflow_definition_zip(),
        requestId=ctx.unique_name("sim2real-wfreq-"),
        tags={"sim2real-audit": "true"},
    )
    workflow_id = created["id"]
    ctx.on_cleanup(lambda: _delete_workflow(omics, workflow_id))

    status = created.get("status")
    deadline = time.monotonic() + 180
    while status not in ("ACTIVE", "FAILED") and time.monotonic() < deadline:
        time.sleep(3)
        status = omics.get_workflow(id=workflow_id)["status"]
    assert status == "ACTIVE", f"workflow {workflow_id} ended in status {status!r}"
    return workflow_id


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-omics-startrun-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    return bucket


def _empty_and_delete_bucket(s3, bucket, timeout_s=120.0, interval_s=5.0):
    """Empty and delete the bucket, re-emptying while Omics still lands run output in it."""
    deadline = time.monotonic() + timeout_s
    while True:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        try:
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "BucketNotEmpty" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _create_omics_trust_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-omics-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "omics.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-audit", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    # StartRun validates the output URI and the run's log/image access synchronously against
    # this role, so the positive-control run needs real permissions, not just a trust policy.
    run_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                    "logs:DescribeLogStreams",
                ],
                "Resource": "arn:aws:logs:*:*:log-group:/aws/omics/WorkflowLog:*",
            },
            {
                "Effect": "Allow",
                "Action": ["ecr:GetAuthorizationToken"],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],
                "Resource": "*",
            },
        ],
    }
    policy_name = ctx.unique_name("sim2real-omics-run-policy-")
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(run_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
