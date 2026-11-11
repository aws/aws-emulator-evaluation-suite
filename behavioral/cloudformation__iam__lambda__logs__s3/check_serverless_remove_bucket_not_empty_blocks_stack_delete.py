"""serverless-remove-bucket-not-empty-blocks-stack-delete."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "serverless-remove-bucket-not-empty-blocks-stack-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam", "lambda", "logs", "s3"]

_SLS_VERSION = "3.40.0"
_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*?) \(Service: (?P<service>[A-Za-z0-9]+), '
    r'Status Code: (?P<status>\d+), Request ID: [A-Za-z0-9]+, Extended Request ID: [A-Za-z0-9+/=]+\)'
    r'(?: \(SDK Attempt Count: \d+\))?" \(RequestToken: [A-Za-z0-9-]+, '
    r'HandlerErrorCode: (?P<handler>[A-Za-z]+)\)$'
)

_HANDLER = '''
def main(event, context):
    return {"ok": True}
'''

_TEMPLATE = """
service: {service}

provider:
  name: aws
  runtime: python3.12
  region: {region}
  stackTags:
    sim2real:managed: "true"
  tags:
    sim2real:managed: "true"

functions:
  hello:
    handler: handler.main

resources:
  Resources:
    DataBucket:
      Type: AWS::S3::Bucket
      Properties:
        Tags:
          - Key: sim2real:managed
            Value: "true"
"""


def _run(args: list[str], *, cwd: str, env: dict, timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(
        args, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout
    )


def _npm_install_serverless(workdir: str, env: dict) -> None:
    pkg = {"name": "sim2real-check", "version": "1.0.0", "private": True,
           "devDependencies": {"serverless": _SLS_VERSION}}
    Path(workdir, "package.json").write_text(json.dumps(pkg))
    # side-channel: the check pins and fetches Serverless Framework v3 from the public npm
    # registry at run time, exactly as a customer deploying with the tool would.
    r = subprocess.run(
        ["npm", "install", "--no-audit", "--no-fund"],
        cwd=workdir, env=env, capture_output=True, text=True, timeout=240,
    )
    assert r.returncode == 0, f"npm install serverless@{_SLS_VERSION} failed: {r.stderr[-2000:]}"


def _sls(args: list[str], *, workdir: str, env: dict, timeout: float) -> subprocess.CompletedProcess:
    return _run(
        ["npx", "--no-install", "serverless", *args],
        cwd=workdir, env=env, timeout=timeout,
    )


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 2.0,
                     budget_s: float = 180.0) -> None:
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


# Serverless Framework 3 calls AWS through the JavaScript SDK v2, which ctx.subprocess_env() points
# at an emulator's endpoint; this preload sends that SDK's S3 requests path-style, so every target is
# sent the same request shape.
_PATH_STYLE_PRELOAD = """
try {
  require(require.resolve("aws-sdk", { paths: [process.cwd()] })).config.update(
    { s3ForcePathStyle: true });
} catch (err) {
  if (err.code !== "MODULE_NOT_FOUND") throw err;
}
"""


def _env_for(ctx, workdir: str) -> dict:
    env = dict(ctx.subprocess_env())
    preload = os.path.join(workdir, "path-style-preload.js")
    with open(preload, "w") as fh:
        fh.write(_PATH_STYLE_PRELOAD)
    # Appended to the NODE_OPTIONS ctx.subprocess_env() sets, so its preload runs first.
    env["NODE_OPTIONS"] = f"{env.get('NODE_OPTIONS', '')} --require \"{preload}\"".lstrip()
    env["SLS_TELEMETRY_DISABLED"] = "1"
    env["CI"] = "1"
    env["NO_COLOR"] = "1"
    return env


def _error(fn) -> tuple[str, str]:
    """The (code, message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return str(exc.response["Error"]["Code"]), str(exc.response["Error"].get("Message", ""))
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _physical_id(resources: list[dict], logical_id: str) -> str:
    ids = [r["PhysicalResourceId"] for r in resources if r["LogicalResourceId"] == logical_id]
    assert len(ids) == 1, f"expected exactly one resource named {logical_id!r}, found {ids!r}"
    return ids[0]


def _empty_bucket(s3, bucket: str) -> None:
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        objects = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
        objects += [
            {"Key": m["Key"], "VersionId": m["VersionId"]} for m in page.get("DeleteMarkers", [])
        ]
        if objects:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:deploy",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """`serverless remove` of a stack whose own S3 bucket still holds an object leaves it
    DELETE_FAILED with S3's BucketNotEmpty reason on that bucket; emptying it lets the retried
    delete complete and remove every resource.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html
    """
    require_tools("npm", "node")

    lam = ctx.client("lambda")
    s3 = ctx.client("s3")
    cfn = ctx.client("cloudformation")

    service = ctx.unique_name("sim2real")
    stage = "dev"
    stack_name = f"{service}-{stage}"
    function_name = f"{service}-{stage}-hello"

    workdir = tempfile.mkdtemp(prefix="sim2real-sls-removefail-")
    # Registered first so LIFO removes the work dir only after every stack teardown.
    ctx.on_cleanup(lambda: shutil.rmtree(workdir, ignore_errors=True))
    env = _env_for(ctx, workdir)
    _npm_install_serverless(workdir, env)
    Path(workdir, "handler.py").write_text(_HANDLER)
    Path(workdir, "serverless.yml").write_text(_TEMPLATE.format(service=service, region=ctx.region))

    def _stack_exists() -> bool:
        try:
            cfn.describe_stacks(StackName=stack_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationError":
                return False
            raise
        return True

    def _delete_stack_and_wait(timeout_s: float = 300.0) -> str:
        cfn.delete_stack(StackName=stack_name)
        deadline = time.monotonic() + timeout_s
        status = ""
        while time.monotonic() < deadline:
            if not _stack_exists():
                return "DELETE_COMPLETE"
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
            if status in ("DELETE_FAILED", "DELETE_COMPLETE"):
                return status
            time.sleep(2.0)
        raise AssertionError(f"stack delete did not settle within {timeout_s}s; last status {status!r}")

    def _cleanup() -> None:
        if not _stack_exists():
            return
        # The check puts a blocking object in DataBucket and the deploy uploads its artifacts to
        # ServerlessDeploymentBucket; empty both whatever state a failed assertion left the stack in.
        buckets = [r["PhysicalResourceId"]
                   for r in cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
                   if r["LogicalResourceId"] in ("DataBucket", "ServerlessDeploymentBucket")
                   and r.get("PhysicalResourceId")]
        for bucket in buckets:
            try:
                _empty_bucket(s3, bucket)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchBucket":
                    raise
        final = _delete_stack_and_wait()
        assert final == "DELETE_COMPLETE", f"cleanup could not delete stack {stack_name!r}: {final!r}"

    ctx.on_cleanup(_cleanup)
    ctx.on_cleanup(lambda: _reap_log_group(logs=ctx.client("logs"), name=f"/aws/lambda/{function_name}"))

    deployed = _sls(["deploy", "--stage", stage], workdir=workdir, env=env, timeout=600)
    assert deployed.returncode == 0, (
        f"serverless deploy failed: {deployed.stderr[-2000:]}\n{deployed.stdout[-2000:]}"
    )

    resources = cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    data_bucket = _physical_id(resources, "DataBucket")
    deployment_bucket = _physical_id(resources, "ServerlessDeploymentBucket")
    role_name = _physical_id(resources, "IamRoleLambdaExecution")
    log_group_name = _physical_id(resources, "HelloLogGroup")

    marker = ctx.unique_name("blocker-")
    s3.put_object(Bucket=data_bucket, Key="blocker.txt", Body=marker.encode())

    # Drive the removal the way a customer would: ``serverless remove``, which empties its OWN
    # deployment bucket before asking CloudFormation to delete the stack. Our extra DataBucket
    # is not its to empty, so this isolates the failure to exactly the resource we broke.
    removed = _sls(["remove", "--stage", stage], workdir=workdir, env=env, timeout=600)
    assert removed.returncode != 0, (
        "serverless remove exited 0 despite an object left in the stack's own bucket; "
        f"stdout={removed.stdout[-1000:]!r}"
    )

    deadline = time.monotonic() + 300.0
    status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    while status == "DELETE_IN_PROGRESS" and time.monotonic() < deadline:
        time.sleep(2.0)
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert status == "DELETE_FAILED", (
        f"stack delete finished as {status!r} with an object still in {data_bucket!r}, "
        "expected CloudFormation to refuse it and leave the stack DELETE_FAILED"
    )

    bucket_events = [
        e
        for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name)
        for e in page["StackEvents"]
        if e.get("LogicalResourceId") == "DataBucket" and e.get("ResourceStatus") == "DELETE_FAILED"
    ]
    assert len(bucket_events) == 1, (
        f"expected one DELETE_FAILED event for DataBucket in {stack_name!r}, got {bucket_events!r}"
    )
    reason = bucket_events[0].get("ResourceStatusReason") or ""
    match = _REASON.match(reason)
    assert match is not None, f"DataBucket's DELETE_FAILED reason is not a handler message: {reason!r}"
    got = (match["message"], match["service"], match["status"], match["handler"])
    want = ("The bucket you tried to delete is not empty", "S3", "409", "GeneralServiceException")
    assert got == want, f"DataBucket's DELETE_FAILED reason: expected {want!r}, got {got!r} in {reason!r}"
    # S3 itself refuses the same delete, and the object that blocks it is intact.
    refused = _error(lambda: s3.delete_bucket(Bucket=data_bucket))
    assert refused == ("BucketNotEmpty", "The bucket you tried to delete is not empty"), (
        f"DeleteBucket on {data_bucket!r} holding an object returned {refused!r}"
    )
    kept = s3.get_object(Bucket=data_bucket, Key="blocker.txt")["Body"].read()
    assert kept == marker.encode(), f"the blocking object reads {kept!r}, expected {marker!r}"

    # serverless's own deployment bucket, which it empties itself, is already gone.
    gone = _error(lambda: s3.get_bucket_versioning(Bucket=deployment_bucket))
    assert gone == ("NoSuchBucket", "The specified bucket does not exist"), (
        f"GetBucketVersioning on the deployment bucket returned {gone!r}"
    )

    # Positive control: emptying the offending bucket lets the very same delete succeed.
    _empty_bucket(s3, data_bucket)
    final_status = _delete_stack_and_wait()
    assert final_status == "DELETE_COMPLETE", (
        f"retrying the delete after emptying {data_bucket!r} finished as {final_status!r}, "
        "expected DELETE_COMPLETE"
    )
    _reap_log_group(ctx.client("logs"), log_group_name)

    gone = _error(lambda: cfn.describe_stacks(StackName=stack_name))
    assert gone == ("ValidationError", f"Stack with id {stack_name} does not exist"), (
        f"DescribeStacks on {stack_name!r} after the retried delete returned {gone!r}"
    )
    fn_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{function_name}"
    gone = _error(lambda: lam.get_function(FunctionName=function_name))
    assert gone == ("ResourceNotFoundException", f"Function not found: {fn_arn}"), (
        f"GetFunction on {function_name!r} after the retried delete returned {gone!r}"
    )
    gone = _error(lambda: ctx.client("iam").get_role(RoleName=role_name))
    assert gone == ("NoSuchEntity", f"The role with name {role_name} cannot be found."), (
        f"GetRole on {role_name!r} after the retried delete returned {gone!r}"
    )
    gone = _error(lambda: s3.get_bucket_versioning(Bucket=data_bucket))
    assert gone == ("NoSuchBucket", "The specified bucket does not exist"), (
        f"GetBucketVersioning on {data_bucket!r} after the retried delete returned {gone!r}"
    )
    gone = _error(lambda: ctx.client("logs").describe_log_streams(logGroupName=log_group_name))
    assert gone == ("ResourceNotFoundException", "The specified log group does not exist."), (
        f"DescribeLogStreams on {log_group_name!r} after the retried delete returned {gone!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
