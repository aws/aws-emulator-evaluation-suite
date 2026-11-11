"""sam-cli-local-application-deploys-nested-stack."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError
from fidelity_tests_runner import RequiredToolMissing

from behavioral_harness import tags

CHECK = "sam-cli-local-application-deploys-nested-stack"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3", "sqs"]

DEPLOYMENTS = Path(__file__).parent / "deployments"
_PROJECT = "sam_cli_nested_app"

_DEADLINE_S = 600.0
_TEMPLATE_FILE = ".aws-sam/build/template.yaml"


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """`sam deploy` turns an AWS::Serverless::Application with a local template into a nested stack.

    `sam build` stages the child, the deploy packages it to the bucket, and the parent's output
    carries the child's queue ARN.

    Reference: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-template-nested-applications.html
    """
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    stack = ctx.unique_name("sim2real-sam-app-")
    bucket = ctx.unique_name("sim2real-sam-app-")
    queue = ctx.unique_name("sim2real-sam-app-")
    work = _workdir(ctx, _PROJECT)

    _make_bucket(ctx, s3, bucket)
    _ok(_sam(ctx, work, ["build", "--region", ctx.region]), "build")
    built = (work / _TEMPLATE_FILE).read_text().splitlines()
    assert "      Location: App/template.yaml" in built, (
        f"sam build must point the application at its built child template; got {built!r}"
    )
    assert (work / ".aws-sam" / "build" / "App" / "template.yaml").is_file(), (
        "sam build must write the child template to .aws-sam/build/App/template.yaml"
    )

    nested: list = []
    ctx.on_cleanup(lambda: _delete_parent_and_nested(cfn, stack, nested))
    _ok(
        _sam(
            ctx,
            work,
            _deploy_args(ctx, stack, bucket, "--parameter-overrides", f"QueueName={queue}"),
        ),
        "deploy",
    )
    parent = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    assert parent["StackStatus"] == "CREATE_COMPLETE", (
        f"the parent stack is {parent['StackStatus']!r}"
    )

    resources = cfn.describe_stack_resources(StackName=parent["StackId"])["StackResources"]
    rows = [(r["LogicalResourceId"], r["ResourceType"], r["ResourceStatus"]) for r in resources]
    assert rows == [("App", "AWS::CloudFormation::Stack", "CREATE_COMPLETE")], (
        f"the parent must hold the application as one nested stack; got {rows!r}"
    )
    nested_id = resources[0]["PhysicalResourceId"]
    nested.append(nested_id)
    child_arn_form = (
        rf"arn:aws:cloudformation:{re.escape(ctx.region)}:{ctx.account}:stack/"
        rf"{re.escape(stack)}-App-[A-Z0-9]+/[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}"
        r"-[0-9a-f]{12}"
    )
    assert re.fullmatch(child_arn_form, nested_id), (
        f"the nested stack's physical id must be its stack ARN; got {nested_id!r}"
    )

    child = cfn.describe_stacks(StackName=nested_id)["Stacks"][0]
    assert (child["StackStatus"], child["ParentId"], child["RootId"]) == (
        "CREATE_COMPLETE",
        parent["StackId"],
        parent["StackId"],
    ), (
        f"the nested stack must be CREATE_COMPLETE with the parent as parent and root; got "
        f"{(child['StackStatus'], child.get('ParentId'), child.get('RootId'))!r}"
    )

    url = _processed(cfn, parent["StackId"])["Resources"]["App"]["Properties"]["TemplateURL"]
    match = re.fullmatch(
        rf"https://[^/]+/{re.escape(bucket)}/({re.escape(stack)}/[0-9a-f]{{32}}\.template)", url
    )
    assert match, (
        f"the nested stack's TemplateURL must name a packaged object in {bucket}; got {url!r}"
    )
    packaged = s3.get_object(Bucket=bucket, Key=match.group(1))["Body"].read().decode()
    original = cfn.get_template(StackName=nested_id, TemplateStage="Original")["TemplateBody"]
    assert original == packaged, "the nested stack must run the packaged child template"

    queue_arn = sqs.get_queue_attributes(
        QueueUrl=sqs.get_queue_url(QueueName=queue)["QueueUrl"], AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]
    outputs = (_outputs(parent), _outputs(child))
    assert outputs == ({"QueueArn": queue_arn}, {"QueueArn": queue_arn}), (
        f"queue ARN {queue_arn!r} must be the child's and the parent's output; got {outputs!r}"
    )


def _outputs(described: dict) -> dict:
    return {o["OutputKey"]: o["OutputValue"] for o in described.get("Outputs", [])}


def _delete_parent_and_nested(cfn, stack: str, nested: list) -> None:
    """Delete the parent and wait until it and each nested stack are DELETE_COMPLETE."""
    _delete_stack_named(cfn, stack)
    for stack_id in nested:
        final = _poll(
            lambda sid=stack_id: _status(cfn, sid),
            lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
            timeout_s=_DEADLINE_S,
            interval_s=5.0,
            what=f"nested stack {stack_id} deleted",
        )
        if final != "DELETE_COMPLETE":
            raise AssertionError(
                f"nested stack {stack_id} ended {final}: {_failures(cfn, stack_id)!r}"
            )


def _sam(ctx, cwd: Path, args: list, *, timeout_s: float = 600.0):
    """Run the SAM CLI in ``cwd`` against the target, with telemetry off."""
    sam = shutil.which("sam")
    if sam is None:
        raise RequiredToolMissing(["sam"])
    ctx.verify_account_safety()
    return subprocess.run(
        [sam, *args],
        cwd=cwd,
        env={**ctx.subprocess_env(), "SAM_CLI_TELEMETRY": "0"},
        capture_output=True,
        text=True,
        timeout=timeout_s,
    )


def _ok(result, what: str) -> None:
    """Assert a SAM CLI run exited 0."""
    assert result.returncode == 0, (
        f"`sam {what}` exited {result.returncode}: {(result.stdout + result.stderr)[-1500:]!r}"
    )


def _deploy_args(ctx, stack: str, bucket: str, *extra: str) -> list:
    """`sam deploy` of the built template into the check's own bucket, never prompting."""
    return [
        "deploy",
        "--template-file",
        _TEMPLATE_FILE,
        "--stack-name",
        stack,
        "--s3-bucket",
        bucket,
        "--s3-prefix",
        stack,
        "--capabilities",
        "CAPABILITY_IAM",
        "CAPABILITY_AUTO_EXPAND",
        "--region",
        ctx.region,
        "--no-confirm-changeset",
        "--no-progressbar",
        "--tags",
        f"sim2real={CHECK}",
        *extra,
    ]


def _workdir(ctx, project: str) -> Path:
    """A scratch copy of the SAM project, so a build never writes into the source tree."""
    root = Path(tempfile.mkdtemp(prefix="sim2real-sam-"))
    ctx.on_cleanup(lambda: shutil.rmtree(root))
    work = root / "app"
    shutil.copytree(DEPLOYMENTS / project, work)
    return work


def _make_bucket(ctx, s3, name: str) -> None:
    """Create the bucket with a teardown that empties and deletes it."""
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":  # the one region that takes no LocationConstraint
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def empty_and_delete() -> None:
        try:
            for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
                for obj in page.get("Contents", []):
                    s3.delete_object(Bucket=name, Key=obj["Key"])
            s3.delete_bucket(Bucket=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(empty_and_delete)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})


def _processed(cfn, stack_id: str) -> dict:
    body = cfn.get_template(StackName=stack_id, TemplateStage="Processed")["TemplateBody"]
    return body if isinstance(body, dict) else json.loads(body)


def _poll(probe, done, *, timeout_s: float, interval_s: float = 3.0, what: str = "condition"):
    """probe() until done(result); returns the result and raises at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _status(cfn, stack_id: str) -> str:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]


def _settle(cfn, stack_id: str) -> str:
    """The stack's next terminal status, so a wrong one is reported rather than timed out."""
    return _poll(
        lambda: _status(cfn, stack_id),
        lambda s: not s.endswith("_IN_PROGRESS"),
        timeout_s=_DEADLINE_S,
        interval_s=5.0,
        what=f"stack {stack_id} settled",
    )


def _failures(cfn, stack_id: str) -> list:
    """(logical id, reason) of every failed resource event, for a failing assert's message."""
    events: list = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return [
        (e["LogicalResourceId"], e.get("ResourceStatusReason"))
        for e in events
        if e["ResourceStatus"].endswith("_FAILED")
    ]


def _delete_stack(cfn, stack_id: str) -> None:
    """Delete by StackId and wait for DELETE_COMPLETE; any other end raises."""
    status = _status(cfn, stack_id)
    if status.endswith("_IN_PROGRESS") and status != "REVIEW_IN_PROGRESS":
        _settle(cfn, stack_id)
    if _status(cfn, stack_id) == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        lambda: _status(cfn, stack_id),
        lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
        timeout_s=_DEADLINE_S,
        interval_s=5.0,
        what=f"stack {stack_id} deleted",
    )
    if final != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} ended {final}: {_failures(cfn, stack_id)!r}")


def _delete_stack_named(cfn, name: str) -> None:
    """Delete the stack a CLI created under ``name``, if it exists, and wait for DELETE_COMPLETE."""
    try:
        stack_id = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {name} does not exist":
            return
        raise
    _delete_stack(cfn, stack_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
