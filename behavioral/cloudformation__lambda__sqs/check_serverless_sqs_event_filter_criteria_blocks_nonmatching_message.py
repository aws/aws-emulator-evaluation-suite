"""serverless-sqs-event-filter-criteria-blocks-nonmatching-message."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "serverless-sqs-event-filter-criteria-blocks-nonmatching-message"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda", "sqs"]

_SLS_VERSION = "3.40.0"

_HANDLER = '''
def main(event, context):
    for record in event.get("Records", []):
        print("PROCESSED " + record.get("body", ""))
    return {"batchItemFailures": []}
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
  consumer:
    handler: handler.main
    events:
      - sqs:
          arn:
            Fn::GetAtt: [SourceQueue, Arn]
          batchSize: 1
          filterPatterns:
            - messageAttributes:
                kind:
                  stringValue: ["process"]

resources:
  Resources:
    SourceQueue:
      Type: AWS::SQS::Queue
      Properties:
        QueueName: {queue_name}
        VisibilityTimeout: 30
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


def _log_contains(logs, log_group: str, needle: str) -> bool:
    try:
        events = logs.filter_log_events(logGroupName=log_group, filterPattern=f'"{needle}"')[
            "events"
        ]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return False
    return any(needle in e["message"] for e in events)


def _error(fn) -> tuple[str, str]:
    """The (code, message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return str(exc.response["Error"]["Code"]), str(exc.response["Error"].get("Message", ""))
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _physical_ids(cfn, stack: str, resource_type: str) -> list[str]:
    return sorted(r["PhysicalResourceId"]
                  for r in cfn.describe_stack_resources(StackName=stack)["StackResources"]
                  if r["ResourceType"] == resource_type)


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "cap:c4",
    "cap:c7",
    "concern:data-plane",
    "concern:deploy",
    "concern:eventing",
    "concern:negative-classes",
    "plane:data",
    "dp:api",
)
def run(ctx) -> None:
    """A Serverless Framework SQS event's filterPatterns reach the mapping as declared: a message
    whose `kind` attribute does not match never invokes the function, while a matching one does.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventfiltering.html
    """
    require_tools("npm", "node")

    sqs = ctx.client("sqs")
    logs = ctx.client("logs")
    lam = ctx.client("lambda")
    cfn = ctx.client("cloudformation")

    service = ctx.unique_name("sim2real")
    stage = "dev"
    queue_name = f"{service}-{stage}-src"
    stack_name = f"{service}-{stage}"
    function_name = f"{service}-{stage}-consumer"

    workdir = tempfile.mkdtemp(prefix="sim2real-sls-sqsfilter-")
    # Registered first so LIFO removes the work dir only after `serverless remove` has run in it.
    ctx.on_cleanup(lambda: shutil.rmtree(workdir, ignore_errors=True))
    env = _env_for(ctx, workdir)
    _npm_install_serverless(workdir, env)
    Path(workdir, "handler.py").write_text(_HANDLER)
    Path(workdir, "serverless.yml").write_text(
        _TEMPLATE.format(service=service, region=ctx.region, queue_name=queue_name)
    )

    def _stack_exists() -> bool:
        try:
            cfn.describe_stacks(StackName=stack_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationError":
                return False
            raise
        return True

    def _remove() -> None:
        if not _stack_exists():
            return
        r = _sls(["remove", "--stage", stage], workdir=workdir, env=env, timeout=600)
        assert r.returncode == 0, f"serverless remove failed: {r.stderr[-2000:]}\n{r.stdout[-2000:]}"

    ctx.on_cleanup(_remove)
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{function_name}"))

    deployed = _sls(["deploy", "--stage", stage], workdir=workdir, env=env, timeout=600)
    assert deployed.returncode == 0, (
        f"serverless deploy failed: {deployed.stderr[-2000:]}\n{deployed.stdout[-2000:]}"
    )

    queue_url = sqs.get_queue_url(QueueName=queue_name)["QueueUrl"]
    role_names = _physical_ids(cfn, stack_name, "AWS::IAM::Role")
    buckets = _physical_ids(cfn, stack_name, "AWS::S3::Bucket")
    assert len(role_names) == 1 and len(buckets) == 1, (
        f"expected one execution role and one deployment bucket, got {role_names!r} {buckets!r}"
    )

    deadline = time.monotonic() + 90.0
    mapping = None
    while time.monotonic() < deadline:
        mappings = lam.list_event_source_mappings(FunctionName=function_name)["EventSourceMappings"]
        assert len(mappings) <= 1, f"expected one mapping on {function_name!r}, got {mappings!r}"
        if mappings and mappings[0]["State"] == "Enabled":
            mapping = mappings[0]
            break
        time.sleep(2.0)
    assert mapping is not None, "event source mapping never reached state Enabled within 90s"
    patterns = [json.loads(f["Pattern"]) for f in mapping.get("FilterCriteria", {}).get("Filters", [])]
    assert patterns == [{"messageAttributes": {"kind": {"stringValue": ["process"]}}}], (
        f"the mapping's FilterCriteria patterns are {patterns!r}, expected the one declared "
        f"filterPatterns entry"
    )

    blocked_marker = ctx.unique_name("blocked-")
    matching_marker = ctx.unique_name("matching-")
    sqs.send_message(
        QueueUrl=queue_url,
        MessageBody=blocked_marker,
        MessageAttributes={"kind": {"DataType": "String", "StringValue": "skip"}},
    )
    sqs.send_message(
        QueueUrl=queue_url,
        MessageBody=matching_marker,
        MessageAttributes={"kind": {"DataType": "String", "StringValue": "process"}},
    )

    log_group = f"/aws/lambda/{function_name}"
    matching_needle = f"PROCESSED {matching_marker}"
    blocked_needle = f"PROCESSED {blocked_marker}"

    # Positive control: the matching message drains and is processed within a bounded window.
    start = time.monotonic()
    deadline = start + 90.0
    drained = False
    while time.monotonic() < deadline:
        if _log_contains(logs, log_group, matching_needle):
            drained = True
            break
        time.sleep(2.0)
    latency_s = time.monotonic() - start
    assert drained, "the matching message was never processed within 90s (control failed)"

    # AWS removes an SQS message that FilterCriteria holds back from the queue without ever
    # invoking the function for it (it is not retried or sent to a DLQ): assert the absence of
    # invocation evidence over a window derived from the positive control's measured latency,
    # and that the queue still fully drains (both messages gone), not that the record lingers.
    window = max(10.0, 3.0 * latency_s)
    window_deadline = time.monotonic() + window
    while time.monotonic() < window_deadline:
        assert not _log_contains(logs, log_group, blocked_needle), (
            f"the non-matching message {blocked_marker!r} was delivered to the function despite "
            "a FilterCriteria pattern that should have held it back"
        )
        time.sleep(2.0)

    deadline = time.monotonic() + 90.0
    fully_drained = False
    while time.monotonic() < deadline:
        attrs = sqs.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"]
        if attrs["ApproximateNumberOfMessages"] == "0" and attrs["ApproximateNumberOfMessagesNotVisible"] == "0":
            fully_drained = True
            break
        time.sleep(2.0)
    assert fully_drained, (
        f"queue {queue_name!r} did not fully drain within 90s: last attrs={attrs!r}"
    )
    assert not _log_contains(logs, log_group, blocked_needle), (
        f"the non-matching message {blocked_marker!r} was delivered to the function despite "
        "a FilterCriteria pattern that should have held it back"
    )

    _remove()
    _reap_log_group(logs, log_group)

    gone = _error(lambda: cfn.describe_stacks(StackName=stack_name))
    assert gone == ("ValidationError", f"Stack with id {stack_name} does not exist"), (
        f"DescribeStacks on {stack_name!r} after serverless remove returned {gone!r}"
    )
    fn_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{function_name}"
    gone = _error(lambda: lam.get_function(FunctionName=function_name))
    assert gone == ("ResourceNotFoundException", f"Function not found: {fn_arn}"), (
        f"GetFunction on {function_name!r} after serverless remove returned {gone!r}"
    )
    gone = _error(lambda: lam.get_event_source_mapping(UUID=mapping["UUID"]))
    assert gone == ("ResourceNotFoundException", "The resource you requested does not exist."), (
        f"GetEventSourceMapping after serverless remove returned {gone!r}"
    )
    gone = _error(lambda: sqs.get_queue_url(QueueName=queue_name))
    assert gone == ("AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist."), (
        f"GetQueueUrl on {queue_name!r} after serverless remove returned {gone!r}"
    )
    gone = _error(lambda: ctx.client("iam").get_role(RoleName=role_names[0]))
    assert gone == ("NoSuchEntity", f"The role with name {role_names[0]} cannot be found."), (
        f"GetRole on the execution role after serverless remove returned {gone!r}"
    )
    gone = _error(lambda: ctx.client("s3").get_bucket_versioning(Bucket=buckets[0]))
    assert gone == ("NoSuchBucket", "The specified bucket does not exist"), (
        f"GetBucketVersioning on the deployment bucket after serverless remove returned {gone!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
