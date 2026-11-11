"""cdk-deploy-log-metric-filter-alarm-ignores-non-matching-events."""

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

CHECK = "cdk-deploy-log-metric-filter-alarm-ignores-non-matching-events"
GROUP = "deploy"
SERVICES = ["cloudformation", "cloudwatch", "logs"]

_APP = "cdk_log_metric_alarm"
_CLI_TIMEOUT_S = 900.0
_POLL_S = 2.0
_ALARM_BUDGET_S = 240.0
_ANALYTICS = re.compile(r"v2:deflate64:[A-Za-z0-9+/]+={0,2}")


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:negative-delivery", "cap:c3", "concern:deploy", "concern:metrics", "dp:api",
      "plane:control", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A deployed alarm's filter ignores non-matching lines while a contrast filter matching the
    same lines alarms; a matching line afterward still reaches the graded alarm.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/MonitoringLogData.html
    """
    require_tools("cdk", "node")
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")

    qualifier = ctx.unique_name("q")[:10]
    toolkit_stack = ctx.unique_name("sim2real-cdktk-")
    stack = ctx.unique_name("sim2real-cdklogalarm-")
    context = {
        "stack_name": stack,
        "account": ctx.account,
        "region": ctx.region,
        "qualifier": qualifier,
        "filter_pattern": '"ERROR"',
        "metric_namespace": ctx.unique_name("sim2real-ns-"),
        "metric_name": "ErrorCount",
        "alarm_name": ctx.unique_name("sim2real-alarm-"),
        "contrast_pattern": '"INFO"',
        "contrast_metric_name": "InfoCount",
        "contrast_alarm_name": ctx.unique_name("sim2real-contrast-"),
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
    log_group_name, alarm_name = outputs["LogGroupName"], outputs["AlarmName"]
    contrast_alarm = outputs["ContrastAlarmName"]

    initial = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"]
    assert initial in ("OK", "INSUFFICIENT_DATA"), f"alarm {alarm_name} started as {initial!r}"

    stream = ctx.unique_name("sim2real-stream-")
    logs.create_log_stream(logGroupName=log_group_name, logStreamName=stream)

    # Break exactly one thing: every line carries no "ERROR" substring, so the graded filter never
    # matches. The contrast filter matches the same lines, so the window lasts until its alarm
    # fires: the graded alarm had the same lines and evaluations and must not be in ALARM.
    contrast_deadline = time.monotonic() + _ALARM_BUDGET_S
    states = _alarm_states(cw, [alarm_name, contrast_alarm])
    while states[contrast_alarm] != "ALARM":
        assert time.monotonic() < contrast_deadline, (
            f"contrast alarm {contrast_alarm} never reached ALARM from matching lines within "
            f"{_ALARM_BUDGET_S}s; last states {states!r}"
        )
        logs.put_log_events(
            logGroupName=log_group_name,
            logStreamName=stream,
            logEvents=[{"timestamp": int(time.time() * 1000), "message": "INFO disk nominal"}],
        )
        time.sleep(_POLL_S)
        states = _alarm_states(cw, [alarm_name, contrast_alarm])
        assert states[alarm_name] != "ALARM", (
            f"alarm {alarm_name} reached ALARM from lines that never match the filter pattern"
        )
    worst_state = states[alarm_name]

    # Repair: a matching line is the positive control — the wiring from filter to alarm works.
    match_deadline = time.monotonic() + _ALARM_BUDGET_S
    state = worst_state
    while state != "ALARM":
        assert time.monotonic() < match_deadline, (
            f"alarm {alarm_name} never reached ALARM from a matching line within "
            f"{_ALARM_BUDGET_S}s; last state {state!r}"
        )
        logs.put_log_events(
            logGroupName=log_group_name,
            logStreamName=stream,
            logEvents=[{"timestamp": int(time.time() * 1000), "message": "ERROR disk full"}],
        )
        time.sleep(_POLL_S)
        state = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"]

    rc, out = _cdk(ctx, work, ["destroy", stack, "--force"], context)
    assert rc == 0, f"`cdk destroy` exited {rc}; output tail {out[-800:]!r}"

    status = cfn.describe_stacks(StackName=deployed["StackId"])["Stacks"][0]["StackStatus"]
    assert status == "DELETE_COMPLETE", f"stack {stack} is {status!r} after `cdk destroy`"
    remaining_groups = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"]
    assert remaining_groups == [], f"log group {log_group_name} still present: {remaining_groups!r}"
    remaining_alarms = cw.describe_alarms(AlarmNames=[alarm_name, contrast_alarm])["MetricAlarms"]
    assert remaining_alarms == [], f"alarms still present: {remaining_alarms!r}"


def _alarm_states(cw, names: list[str]) -> dict[str, str]:
    """StateValue of each named metric alarm."""
    alarms = cw.describe_alarms(AlarmNames=names)["MetricAlarms"]
    states = {a["AlarmName"]: a["StateValue"] for a in alarms}
    assert sorted(states) == sorted(names), f"DescribeAlarms for {names!r} returned {sorted(states)!r}"
    return states


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
