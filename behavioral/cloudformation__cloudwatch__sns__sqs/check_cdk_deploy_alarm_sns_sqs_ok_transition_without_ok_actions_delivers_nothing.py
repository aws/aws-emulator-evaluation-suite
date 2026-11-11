"""cdk-deploy-alarm-sns-sqs-ok-transition-without-ok-actions-delivers-nothing."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cdk-deploy-alarm-sns-sqs-ok-transition-without-ok-actions-delivers-nothing"
GROUP = "deploy"
SERVICES = ["cloudformation", "cloudwatch", "sns", "sqs"]

_APP = "cdk_alarm_sns_sqs"
_CLI_TIMEOUT_S = 900.0
_POLL_S = 2.0
_DELIVERY_BUDGET_S = 120.0
_ANALYTICS = re.compile(r"v2:deflate64:[A-Za-z0-9+/]+={0,2}")


@tags(
    "axis:negative-delivery", "cap:c3", "concern:deploy", "concern:eventing", "dp:api",
    "plane:control", "plane:data",
)
def run(ctx) -> None:
    """A `cdk deploy`-created alarm with only an SNS `AlarmActions` never notifies on OK, while its
    ALARM transitions deliver a notification naming the alarm to the subscribed queue.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
    """
    require_tools("cdk", "node")
    cfn = ctx.client("cloudformation")
    cw = ctx.client("cloudwatch")
    sqs = ctx.client("sqs")

    qualifier = ctx.unique_name("q")[:10]
    toolkit_stack = ctx.unique_name("sim2real-cdktk-")
    stack = ctx.unique_name("sim2real-cdkalarmsns-")
    context = {
        "stack_name": stack,
        "account": ctx.account,
        "region": ctx.region,
        "qualifier": qualifier,
        "metric_namespace": ctx.unique_name("sim2real-ns-"),
        "metric_name": "DummyMetric",
        "alarm_name": ctx.unique_name("sim2real-alarm-"),
    }
    work = _stage_app(ctx)
    _bootstrap(ctx, qualifier, toolkit_stack)
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))

    rc, out = _cdk(
        ctx,
        work,
        [
            "deploy",
            stack,
            "--require-approval",
            "never",
            "--toolkit-stack-name",
            toolkit_stack,
            "--tags",
            f"sim2real={CHECK}",
        ],
        context,
    )
    assert rc == 0, f"`cdk deploy` exited {rc}; output tail {out[-800:]!r}"

    deployed = _deployed(cfn, stack)
    _assert_metadata(cfn, deployed["StackId"])
    outputs = _outputs(deployed)
    queue_url, topic_arn, alarm_name = (
        outputs["QueueUrl"], outputs["TopicArn"], outputs["AlarmName"]
    )

    description = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]
    assert description.get("OKActions", []) == [], (
        f"alarm {alarm_name} unexpectedly carries OKActions {description.get('OKActions')!r}"
    )

    # Warm-up / positive control: measure how long an ALARM transition takes to arrive, so the
    # OK-transition absence window below is sized by this alarm's own observed latency.
    cw.set_alarm_state(AlarmName=alarm_name, StateValue="OK", StateReason="sim2real warm-up reset")
    _drain(sqs, queue_url)
    warm_marker = ctx.unique_name("sim2real-reason-")
    start = time.monotonic()
    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason=warm_marker)
    _poll_for_marker(sqs, queue_url, warm_marker)
    latency_s = time.monotonic() - start

    # Break exactly one thing: transitioning to OK, which carries no configured action.
    ok_marker = ctx.unique_name("sim2real-reason-")
    cw.set_alarm_state(AlarmName=alarm_name, StateValue="OK", StateReason=ok_marker)
    seen = _absent_for(sqs, queue_url, ok_marker, latency_s)
    assert seen == [], f"{len(seen)} notification(s) arrived for an OK transition: {seen!r}"

    # Repair: ALARM is still configured and still delivers.
    alarm_marker = ctx.unique_name("sim2real-reason-")
    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason=alarm_marker)
    body = _poll_for_marker(sqs, queue_url, alarm_marker)
    alarm_arn = f"arn:aws:cloudwatch:{ctx.region}:{ctx.account}:alarm:{alarm_name}"
    got = (body["AlarmName"], body["AlarmArn"], body["NewStateValue"], body["NewStateReason"])
    assert got == (alarm_name, alarm_arn, "ALARM", alarm_marker), (
        f"the ALARM notification carries (AlarmName, AlarmArn, NewStateValue, NewStateReason) {got!r}"
    )

    rc, out = _cdk(ctx, work, ["destroy", stack, "--force"], context)
    assert rc == 0, f"`cdk destroy` exited {rc}; output tail {out[-800:]!r}"

    status = cfn.describe_stacks(StackName=deployed["StackId"])["Stacks"][0]["StackStatus"]
    assert status == "DELETE_COMPLETE", f"stack {stack} is {status!r} after `cdk destroy`"
    remaining_alarms = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"]
    assert remaining_alarms == [], f"alarm {alarm_name} still present: {remaining_alarms!r}"
    got = _error(lambda: sqs.get_queue_attributes(QueueUrl=queue_url))
    assert got == ("AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist."), (
        f"the deleted queue's GetQueueAttributes gave {got!r}"
    )
    got = _error(lambda: ctx.client("sns").get_topic_attributes(TopicArn=topic_arn))
    assert got == ("NotFound", "Topic does not exist"), (
        f"the deleted topic's GetTopicAttributes gave {got!r}"
    )


def _drain(sqs, queue_url: str) -> None:
    """Receive and delete whatever already sits on the queue before the test begins."""
    while True:
        got = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1, VisibilityTimeout=0
        ).get("Messages", [])
        if not got:
            return
        for message in got:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])


def _poll_for_marker(sqs, queue_url: str, marker: str) -> dict:
    """The first delivered notification body whose `NewStateReason` is ``marker``."""
    deadline = time.monotonic() + _DELIVERY_BUDGET_S
    while True:
        got = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1, VisibilityTimeout=0
        ).get("Messages", [])
        for message in got:
            envelope = json.loads(message["Body"])
            body = json.loads(envelope["Message"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])
            if body.get("NewStateReason") == marker:
                return body
        assert time.monotonic() < deadline, f"no notification carrying {marker!r} arrived"
        time.sleep(_POLL_S)


def _absent_for(sqs, queue_url: str, marker: str, latency_s: float) -> list[dict]:
    """Every notification carrying ``marker`` seen over ``max(10s, 3 * latency_s)``."""
    window = max(10.0, 3.0 * latency_s)
    deadline = time.monotonic() + window
    seen: list[dict] = []
    while True:
        got = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1, VisibilityTimeout=0
        ).get("Messages", [])
        for message in got:
            envelope = json.loads(message["Body"])
            body = json.loads(envelope["Message"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])
            if body.get("NewStateReason") == marker:
                seen.append(body)
        if time.monotonic() >= deadline:
            return seen
        time.sleep(_POLL_S)


def _error(fn) -> tuple:
    """(Error.Code, Error.Message) ``fn`` raises. An unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


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


def _cli_env(ctx) -> dict[str, str]:
    """The target's subprocess env with CDK CLI telemetry off."""
    env = ctx.subprocess_env()
    env["CDK_DISABLE_CLI_TELEMETRY"] = "true"
    return env


def _cdk(ctx, work: Path, args: list[str], context: dict[str, str]) -> tuple[int, str]:
    """Run the CDK CLI with its default version reporting; returns (exit code, stdout + stderr)."""
    cmd = ["cdk", *args, "--app", f"{sys.executable} app.py", "--ci", "--no-color", "--no-notices"]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    done = subprocess.run(
        cmd, cwd=work, env=_cli_env(ctx), capture_output=True, text=True, timeout=_CLI_TIMEOUT_S
    )
    return done.returncode, done.stdout + done.stderr


def _deployed(cfn, name: str) -> dict:
    """The stack's description, which must be CREATE_COMPLETE."""
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"stack {name} is {stack['StackStatus']!r} after `cdk deploy`: "
        f"{stack.get('StackStatusReason')!r}"
    )
    return stack


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _assert_metadata(cfn, stack_id: str) -> None:
    """The stack holds a created `CDKMetadata` resource whose template carries `Analytics`."""
    resources = cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    found = [
        (r["ResourceType"], r["ResourceStatus"])
        for r in resources
        if r["LogicalResourceId"] == "CDKMetadata"
    ]
    assert found == [("AWS::CDK::Metadata", "CREATE_COMPLETE")], (
        f"DescribeStackResources on {stack_id} lists CDKMetadata as {found!r}"
    )
    body = cfn.get_template(StackName=stack_id, TemplateStage="Original")["TemplateBody"]
    template = json.loads(body) if isinstance(body, str) else body
    metadata = template["Resources"].get("CDKMetadata", {})
    analytics = metadata.get("Properties", {}).get("Analytics", "")
    assert _ANALYTICS.fullmatch(analytics), f"CDKMetadata Analytics is {analytics!r}"


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
        time.sleep(2.0)


def _bootstrap(ctx, qualifier: str, toolkit_stack: str) -> None:
    """`cdk bootstrap` for a per-run qualifier; what it creates is torn down by this run."""
    s3 = ctx.client("s3")
    bucket = f"cdk-{qualifier}-assets-{ctx.account}-{ctx.region}"
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    ctx.on_cleanup(lambda: _delete_stack(ctx.client("cloudformation"), toolkit_stack))
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-cdk-boot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    cmd = [
        "cdk",
        "bootstrap",
        f"aws://{ctx.account}/{ctx.region}",
        "--qualifier",
        qualifier,
        "--toolkit-stack-name",
        toolkit_stack,
        "--bootstrap-kms-key-id",
        "AWS_MANAGED_KEY",
        "--ci",
        "--no-color",
        "--no-notices",
    ]
    done = subprocess.run(
        cmd, cwd=scratch, env=_cli_env(ctx), capture_output=True, text=True, timeout=_CLI_TIMEOUT_S
    )
    assert done.returncode == 0, (
        f"`cdk bootstrap` exited {done.returncode}; output tail "
        f"{(done.stdout + done.stderr)[-800:]!r}"
    )


def _delete_bucket(s3, bucket: str) -> None:
    """Purge every object version and delete marker, then delete the bucket."""
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objects = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objects:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get(
                    "Errors", []
                )
                assert not failed, f"DeleteObjects in {bucket} left {failed!r}"
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
