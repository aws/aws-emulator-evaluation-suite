"""cdk-deploy-tags-update-with-reserved-aws-prefix-key-rejected-leaving-tags-unchanged."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cdk-deploy-tags-update-with-reserved-aws-prefix-key-rejected-leaving-tags-unchanged"
GROUP = "deploy"
SERVICES = ["cloudformation", "sns", "sqs"]

_DEPLOY_TIMEOUT_S = 300.0
_DESTROY_TIMEOUT_S = 300.0

_APP = "cdk_tags"


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A redeploy whose `--tags` key starts with the AWS-reserved `aws:` prefix is refused by
    CloudFormation, and the queue's and topic's own tags stay exactly what the first deploy set.
    """
    ctx.verify_account_safety()
    from fidelity_tests_runner import require_tools

    require_tools("cdk", "node")

    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")

    prefix = ctx.unique_name("sim2real-cdktagrej-")
    stack = f"{prefix}-stack"
    toolkit_stack = f"{prefix}-toolkit"
    queue_name = ctx.unique_name("sim2real-cdktagrej-q-")
    topic_name = ctx.unique_name("sim2real-cdktagrej-t-")
    good_key = ctx.unique_name("sim2real-goodtag-")
    good_value = ctx.unique_name("goodv-")
    construct_key = ctx.unique_name("sim2real-constructtag-")
    construct_value = ctx.unique_name("constrv-")
    reserved_key = "aws:" + ctx.unique_name("sim2real-reserved-")
    reserved_value = ctx.unique_name("reservedv-")

    work = _stage_app(ctx, _APP)
    ctx.on_cleanup(lambda: _teardown(ctx, stack))
    deploy_context = {
        "account": ctx.account, "region": ctx.region, "stack": stack,
        "queue_name": queue_name, "topic_name": topic_name,
        "tag_key": construct_key, "tag_value": construct_value,
    }

    # ---- 1. Setup: a successful deploy tags the stack and (via propagation) its resources -------
    _cdk(ctx, work, ["deploy", "--require-approval", "never", "--toolkit-stack-name",
                     toolkit_stack, "--tags", f"{good_key}={good_value}"],
         deploy_context, timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)

    outputs = _describe_outputs(cfn, stack)
    queue_url = outputs["QueueUrl"]
    topic_arn = outputs["TopicArn"]
    before_queue_tags = sqs.list_queue_tags(QueueUrl=queue_url).get("Tags", {})
    before_topic_tags = {t["Key"]: t["Value"] for t in
                         sns.list_tags_for_resource(ResourceArn=topic_arn)["Tags"]}
    assert before_queue_tags.get(good_key) == good_value, (
        f"setup: ListQueueTags returned {before_queue_tags!r}, expected the first deploy's tag "
        f"{good_key!r}={good_value!r}"
    )
    assert before_topic_tags.get(good_key) == good_value, (
        f"setup: ListTagsForResource returned {before_topic_tags!r}, expected the first "
        f"deploy's tag {good_key!r}={good_value!r}"
    )

    # ---- 2. NEGATIVE: an update tagging the stack with a reserved `aws:` key is refused ---------
    rc, _ = _cdk(ctx, work, ["deploy", "--require-approval", "never", "--toolkit-stack-name",
                             toolkit_stack, "--tags", f"{reserved_key}={reserved_value}"],
                deploy_context, timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=None)
    assert rc != 0, (
        f"`cdk deploy --tags {reserved_key}={reserved_value}` exited 0; CloudFormation must "
        f"refuse a tag key starting with the AWS-reserved 'aws:' prefix"
    )
    status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
    assert status == "CREATE_COMPLETE", (
        f"stack {stack!r} ended at {status!r} after the refused update, expected it to stay at "
        f"CREATE_COMPLETE — the reserved-prefix tag must be refused before any change is applied"
    )

    # CDK's own `CreateChangeSet` call fails synchronously (no change set is ever persisted, so
    # there is nothing for `ListChangeSets` to show); reproduce the same AWS call directly to
    # read CloudFormation's own refusal rather than relying on the CLI's stdout for it.
    code, message = _create_change_set_error(cfn, stack, reserved_key, reserved_value)
    assert code == "ValidationError", f"CreateChangeSet's error code was {code!r}, expected ValidationError"
    expected_message = "aws: prefixed tag key names are not allowed for external use."
    assert message == expected_message, (
        f"CreateChangeSet's error message was {message!r}, expected exactly {expected_message!r}"
    )

    # ---- 3. The queue's and topic's own tags are untouched by the refused update -----------------
    after_queue_tags = sqs.list_queue_tags(QueueUrl=queue_url).get("Tags", {})
    assert after_queue_tags == before_queue_tags, (
        f"ListQueueTags returned {after_queue_tags!r} after the refused update, expected it "
        f"unchanged from {before_queue_tags!r}"
    )
    after_topic_tags = {t["Key"]: t["Value"] for t in
                        sns.list_tags_for_resource(ResourceArn=topic_arn)["Tags"]}
    assert after_topic_tags == before_topic_tags, (
        f"ListTagsForResource returned {after_topic_tags!r} after the refused update, expected "
        f"it unchanged from {before_topic_tags!r}"
    )
    assert reserved_key not in after_queue_tags and reserved_key not in after_topic_tags, (
        f"the refused tag {reserved_key!r} leaked onto the queue ({after_queue_tags!r}) or the "
        f"topic ({after_topic_tags!r})"
    )


def _describe_outputs(cfn, stack: str) -> dict[str, str]:
    outputs = cfn.describe_stacks(StackName=stack)["Stacks"][0].get("Outputs", [])
    return {o["OutputKey"]: o["OutputValue"] for o in outputs}


def _create_change_set_error(cfn, stack: str, tag_key: str, tag_value: str) -> tuple[str, str]:
    """`(Code, Message)` of the ClientError CreateChangeSet raises tagging *stack* with the
    same reserved-prefix key `cdk deploy --tags` just tried; an unexpected success raises too.
    """
    template = cfn.get_template(StackName=stack)["TemplateBody"]
    try:
        result = cfn.create_change_set(
            StackName=stack, TemplateBody=json.dumps(template), ChangeSetType="UPDATE",
            ChangeSetName=f"{stack}-rejected-tag-probe",
            Tags=[{"Key": tag_key, "Value": tag_value}],
        )
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"CreateChangeSet unexpectedly succeeded: {result!r}")


def _stage_app(ctx, name: str) -> Path:
    """Copy `deployments/<name>` into a temp dir so `cdk.out` never lands in the repo."""
    source = Path(__file__).parent / "deployments" / name
    assert source.is_dir(), (
        f"the CDK app this check references is missing from disk: {source} does not exist "
        f"(artifact defect, not a missing prerequisite)"
    )
    assert (source / "app.py").is_file() and (source / "cdk.json").is_file(), (
        f"the CDK app at {source} is incomplete: app.py present="
        f"{(source / 'app.py').is_file()}, cdk.json present={(source / 'cdk.json').is_file()}"
    )
    work = Path(tempfile.mkdtemp(prefix=f"sim2real-{name}-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    staged = work / name
    shutil.copytree(source, staged, ignore=shutil.ignore_patterns(
        "cdk.out", "out-*", ".venv", "__pycache__", "node_modules"))
    return staged


def _cdk(ctx, work: Path, args: list[str], context: dict[str, str], *, timeout_s: float,
         expect_rc: int | None) -> tuple[int, str]:
    ctx.verify_account_safety()
    cmd = ["cdk", *args, "--ci", "--no-version-reporting", "--no-notices", "--no-color"]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    result = subprocess.run(cmd, cwd=work, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=timeout_s)
    output = result.stdout + result.stderr
    if expect_rc is not None:
        assert result.returncode == expect_rc, (
            f"`cdk {' '.join(args)}` exited {result.returncode}, expected {expect_rc}; output "
            f"tail: {output[-1200:]!r}"
        )
    return result.returncode, output


def _is_stack_not_found(exc: ClientError) -> bool:
    error = exc.response.get("Error", {})
    return (error.get("Code") == "ValidationError"
            and "does not exist" in str(error.get("Message", "")))


def _delete_stack_and_wait(ctx, stack: str, *, timeout_s: float = 300.0) -> None:
    cfn = ctx.client("cloudformation")
    try:
        found = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    except ClientError as exc:
        if _is_stack_not_found(exc):
            return
        raise
    stack_id = found["StackId"]
    if found["StackStatus"] == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    last = "never read"
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last == "DELETE_COMPLETE":
            return
        if last == "DELETE_FAILED":
            raise AssertionError(f"stack {stack!r} reached DELETE_FAILED during teardown")
        time.sleep(5.0)
    raise AssertionError(
        f"stack {stack!r} did not reach DELETE_COMPLETE within {timeout_s}s (last status {last!r})"
    )


def _teardown(ctx, stack: str) -> None:
    _delete_stack_and_wait(ctx, stack, timeout_s=_DESTROY_TIMEOUT_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
