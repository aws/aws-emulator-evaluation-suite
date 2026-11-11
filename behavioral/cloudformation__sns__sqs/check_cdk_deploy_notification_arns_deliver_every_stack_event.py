"""cdk-deploy-notification-arns-deliver-every-stack-event."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cdk-deploy-notification-arns-deliver-every-stack-event"
GROUP = "deploy"
SERVICES = ["cloudformation", "sns", "sqs"]

_APP = "cdk_notification_arns"
_DELIVERY_BUDGET_S = 90.0


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:eventing", "plane:control")
def run(ctx) -> None:
    """`cdk deploy --notification-arns` records the topic on the stack, resolves it through
    AWS::NotificationARNs, and the topic delivers one message for every stack event of the create.
    """
    require_tools("cdk", "node")
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    stack = ctx.unique_name("sim2real-cdk-notify-")
    name = ctx.unique_name("sim2real-cdk-notify-")
    work = _stage_app(ctx)

    topic = sns.create_topic(Name=name, Tags=[{"Key": "sim2real-check", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(_teardown(lambda: sns.delete_topic(TopicArn=topic), "NotFound"))
    url = sqs.create_queue(QueueName=name, tags={"sim2real-check": CHECK})["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url),
                             "AWS.SimpleQueueService.NonExistentQueue"))
    queue_arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
                       "Action": "sqs:SendMessage", "Resource": queue_arn,
                       "Condition": {"ArnEquals": {"aws:SourceArn": topic}}}]})})
    sub = sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=queue_arn,
                        Attributes={"RawMessageDelivery": "true"}, ReturnSubscriptionArn=True)
    ctx.on_cleanup(_teardown(lambda: sns.unsubscribe(SubscriptionArn=sub["SubscriptionArn"]),
                             "NotFound"))
    sns.publish(TopicArn=topic, Message="wiring")
    probe = _drain(sqs, url, lambda bodies: "wiring" in bodies)
    # SNS to SQS delivery is at-least-once, so a duplicate copy of the probe is allowed.
    assert set(probe) == {"wiring"}, f"the topic-to-queue wiring delivered {probe!r}"

    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))
    rc, out = _cdk(ctx, work, ["deploy", stack, "--require-approval", "never",
                               "--notification-arns", topic,
                               "--tags", f"sim2real-check={CHECK}"],
                   {"stack_name": stack, "account": ctx.account, "region": ctx.region})
    assert rc == 0, f"the deploy exited {rc}; output tail {out[-800:]!r}"
    described = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in described.get("Outputs", [])}
    assert (described["NotificationARNs"], outputs) == ([topic], {"NotificationArns": topic}), (
        f"the stack records NotificationARNs {described['NotificationARNs']!r} and outputs {outputs!r}"
    )
    events = {e["EventId"]: (e["LogicalResourceId"], e["ResourceStatus"])
              for e in _events(cfn, described["StackId"])}
    bodies = _drain(sqs, url, lambda got: set(events) <= {_fields(b).get("EventId") for b in got})
    delivered = {}
    for body in bodies:
        fields = _fields(body)
        assert fields.get("StackName") == stack, f"a notification names stack {fields.get('StackName')!r}"
        delivered[fields["EventId"]] = (fields["LogicalResourceId"], fields["ResourceStatus"])
    assert delivered == events, (
        f"the topic delivered {sorted(delivered.values())!r} for stack events {sorted(events.values())!r}"
    )


def _fields(body: str) -> dict[str, str]:
    """The Key='value' lines of a stack notification."""
    out = {}
    for line in body.splitlines():
        key, sep, value = line.partition("=")
        if sep and value.startswith("'") and value.endswith("'"):
            out[key] = value[1:-1]
    return out


def _drain(sqs, url: str, done) -> list[str]:
    """Receive and delete messages until ``done(bodies)`` holds; raises when the budget runs out."""
    deadline = time.monotonic() + _DELIVERY_BUDGET_S
    bodies: list[str] = []
    while not done(bodies):
        if time.monotonic() > deadline:
            raise AssertionError(f"after {_DELIVERY_BUDGET_S}s the queue had delivered {bodies!r}")
        for message in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                           WaitTimeSeconds=5).get("Messages", []):
            bodies.append(message["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=message["ReceiptHandle"])
    return bodies


def _stage_app(ctx) -> Path:
    """Copy the CDK app into a temp dir so cdk.out stays out of the app directory."""
    source = Path(__file__).parent / "deployments" / _APP
    assert (source / "app.py").is_file() and (source / "cdk.json").is_file(), (
        f"the CDK app at {source} is missing app.py or cdk.json"
    )
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdk-app-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    shutil.copytree(source, work / _APP, ignore=shutil.ignore_patterns("cdk.out", "__pycache__"))
    return work / _APP


def _cdk(ctx, work: Path, args: list[str], context: dict[str, str], *,
         timeout_s: float = 600.0) -> tuple[int, str]:
    """Run the CDK CLI against the target; returns (exit code, stdout + stderr)."""
    cmd = ["cdk", *args, "--app", f"{sys.executable} app.py", "--ci", "--no-color",
           "--no-notices", "--no-version-reporting"]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    env = ctx.subprocess_env()
    env["CDK_DISABLE_CLI_TELEMETRY"] = "true"
    done = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True, timeout=timeout_s)
    return done.returncode, done.stdout + done.stderr


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first."""
    pages = cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id)
    return [e for page in pages for e in page["StackEvents"]][::-1]


def _delete_stack(cfn, name: str, *, timeout_s: float = 600.0) -> None:
    """Delete the stack by id and wait for DELETE_COMPLETE; a stack never created is a no-op."""
    try:
        stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {name} does not exist":
            return
        raise
    stack_id = stack["StackId"]
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED" or time.monotonic() > deadline:
            raise AssertionError(f"stack {name} teardown ended {status!r}")
        time.sleep(5.0)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()``; only the resource's own not-found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
