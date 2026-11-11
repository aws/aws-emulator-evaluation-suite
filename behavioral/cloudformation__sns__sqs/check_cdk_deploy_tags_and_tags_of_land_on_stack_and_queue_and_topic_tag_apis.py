"""cdk-deploy-tags-and-tags-of-land-on-stack-and-queue-and-topic-tag-apis."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cdk-deploy-tags-and-tags-of-land-on-stack-and-queue-and-topic-tag-apis"
GROUP = "deploy"
SERVICES = ["cloudformation", "sns", "sqs"]

_DEPLOY_TIMEOUT_S = 300.0
_DESTROY_TIMEOUT_S = 300.0

_APP = "cdk_tags"


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """`--tags` on `cdk deploy` lands on the stack and propagates to the queue/topic it created;
    `Tags.of(stack).add()` lands on those same resources directly, never on the stack itself.
    Both are read back via ListQueueTags and ListTagsForResource.
    """
    ctx.verify_account_safety()
    from fidelity_tests_runner import require_tools

    require_tools("cdk", "node")

    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")

    prefix = ctx.unique_name("sim2real-cdktag-")
    stack = f"{prefix}-stack"
    toolkit_stack = f"{prefix}-toolkit"
    queue_name = ctx.unique_name("sim2real-cdktag-q-")
    topic_name = ctx.unique_name("sim2real-cdktag-t-")
    cli_key = ctx.unique_name("sim2real-clitag-")
    cli_value = ctx.unique_name("cliv-")
    construct_key = ctx.unique_name("sim2real-constructtag-")
    construct_value = ctx.unique_name("constrv-")

    work = _stage_app(ctx, _APP)
    ctx.on_cleanup(lambda: _teardown(ctx, stack))
    deploy_flags = [
        "--require-approval", "never", "--toolkit-stack-name", toolkit_stack,
        "--tags", f"{cli_key}={cli_value}",
    ]

    _cdk(ctx, work, ["deploy", *deploy_flags],
         {"account": ctx.account, "region": ctx.region, "stack": stack,
          "queue_name": queue_name, "topic_name": topic_name,
          "tag_key": construct_key, "tag_value": construct_value},
         timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)

    outputs = _describe_outputs(cfn, stack)
    queue_url = outputs["QueueUrl"]
    topic_arn = outputs["TopicArn"]

    # ---- 1. Only the CLI `--tags` flag reaches the stack's own Tags; `Tags.of()` targeted the --
    #         resources inside it, never the stack construct itself.
    stack_tags = _describe_stack_tags(cfn, stack)
    assert stack_tags == {cli_key: cli_value}, (
        f"DescribeStacks Tags for {stack!r} is {stack_tags!r}, expected exactly the CLI tag "
        f"{cli_key!r}={cli_value!r} — the `Tags.of(stack).add()` construct tag "
        f"{construct_key!r} is never a stack-level tag"
    )

    # ---- 2. THE HEADLINE: the construct-level tag reaches the queue and the topic --------------
    queue_tags = sqs.list_queue_tags(QueueUrl=queue_url).get("Tags", {})
    assert queue_tags.get(construct_key) == construct_value, (
        f"ListQueueTags({queue_url!r}) returned {queue_tags!r}, expected it to carry the "
        f"construct-level tag {construct_key!r}={construct_value!r} that `Tags.of(stack).add()` "
        f"set on every taggable resource in the stack"
    )
    topic_tags = {t["Key"]: t["Value"] for t in
                  sns.list_tags_for_resource(ResourceArn=topic_arn)["Tags"]}
    assert topic_tags.get(construct_key) == construct_value, (
        f"ListTagsForResource({topic_arn!r}) returned {topic_tags!r}, expected it to carry the "
        f"construct-level tag {construct_key!r}={construct_value!r} that `Tags.of(stack).add()` "
        f"set on every taggable resource in the stack"
    )

    # ---- 3. The CLI-level `--tags` flag also reaches both resources, via CloudFormation's own --
    #         stack-tag propagation to every resource type that supports tagging.
    assert queue_tags.get(cli_key) == cli_value, (
        f"ListQueueTags({queue_url!r}) returned {queue_tags!r}, expected it to also carry the "
        f"stack-level `--tags` flag's tag {cli_key!r}={cli_value!r}, which CloudFormation "
        f"propagates from the stack to every resource that supports tagging"
    )
    assert topic_tags.get(cli_key) == cli_value, (
        f"ListTagsForResource({topic_arn!r}) returned {topic_tags!r}, expected it to also carry "
        f"the stack-level `--tags` flag's tag {cli_key!r}={cli_value!r}, which CloudFormation "
        f"propagates from the stack to every resource that supports tagging"
    )


def _describe_outputs(cfn, stack: str) -> dict[str, str]:
    outputs = cfn.describe_stacks(StackName=stack)["Stacks"][0].get("Outputs", [])
    return {o["OutputKey"]: o["OutputValue"] for o in outputs}


def _describe_stack_tags(cfn, stack: str) -> dict[str, str]:
    stack_tags = cfn.describe_stacks(StackName=stack)["Stacks"][0].get("Tags", [])
    return {t["Key"]: t["Value"] for t in stack_tags}


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
