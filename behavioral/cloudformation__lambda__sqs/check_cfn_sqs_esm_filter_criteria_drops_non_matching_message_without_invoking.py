"""cfn-sqs-esm-filter-criteria-drops-non-matching-message-without-invoking."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-sqs-esm-filter-criteria-drops-non-matching-message-without-invoking"
GROUP = "deploy-esm"
SERVICES = ["cloudformation", "lambda", "sqs"]

_FILTER_PATTERN = json.dumps({"body": {"kind": ["process"]}})
_STACK_DEADLINE_S = 300.0
_ESM_ENABLED_TIMEOUT_S = 90.0


def _template(tok: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "SourceQueue": {"Type": "AWS::SQS::Queue",
                            "Properties": {"QueueName": f"{tok}-src", "VisibilityTimeout": 60}},
            "ExecRole": {"Type": "AWS::IAM::Role", "Properties": {
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole"}]},
                "ManagedPolicyArns": [
                    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
                    "arn:aws:iam::aws:policy/service-role/AWSLambdaSQSQueueExecutionRole"],
                "Policies": [{"PolicyName": "send-marker", "PolicyDocument": {
                    "Version": "2012-10-17", "Statement": [{
                        "Effect": "Allow", "Action": "sqs:SendMessage",
                        "Resource": {"Ref": "MarkerQueueArnParam"}}]}}]}},
            "ConsumerFn": {"Type": "AWS::Lambda::Function", "Properties": {
                "FunctionName": f"{tok}-fn", "Runtime": "python3.12", "Handler": "index.handler",
                "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]}, "Timeout": 30,
                "Code": {"ZipFile": (
                    "import json, os\n"
                    "import boto3\n"
                    "def handler(event, context):\n"
                    "    sqs = boto3.client('sqs')\n"
                    "    for r in event.get('Records', []):\n"
                    "        body = json.loads(r['body'])\n"
                    "        sqs.send_message(QueueUrl=os.environ['MARKER_QUEUE_URL'],\n"
                    "            MessageBody=json.dumps({'orderId': body['orderId']}))\n"
                    "    return {'processed': len(event.get('Records', []))}\n"
                )},
                "Environment": {"Variables": {"MARKER_QUEUE_URL": {"Ref": "MarkerQueueParam"}}},
            }},
            "Esm": {"Type": "AWS::Lambda::EventSourceMapping", "Properties": {
                "EventSourceArn": {"Fn::GetAtt": ["SourceQueue", "Arn"]},
                "FunctionName": {"Ref": "ConsumerFn"}, "BatchSize": 1, "Enabled": True,
                "FilterCriteria": {"Filters": [{"Pattern": _FILTER_PATTERN}]}}},
        },
        "Parameters": {"MarkerQueueParam": {"Type": "String"}, "MarkerQueueArnParam": {"Type": "String"}},
        "Outputs": {
            "SourceQueueUrl": {"Value": {"Ref": "SourceQueue"}},
            "FunctionName": {"Value": {"Ref": "ConsumerFn"}},
        },
    })


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:deploy", "concern:eventing",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN EventSourceMapping reads back with its declared FilterCriteria, and the filter is
    enforced: a non-matching message is dropped from the queue without invoking the function,
    while a matching one is delivered; deleting the stack removes the mapping, function and queue."""
    sqs = ctx.client("sqs")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    marker_name = ctx.unique_name("sim2real-esmf-marker-")
    marker_url = sqs.create_queue(QueueName=marker_name,
                                  Attributes={"MessageRetentionPeriod": "3600"})["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_queue(sqs, marker_url))
    marker_arn = sqs.get_queue_attributes(
        QueueUrl=marker_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    stack = _Stack(ctx, ctx.unique_name("sim2real-esmf-"))
    # Registered before the create, so LIFO reaps the function's log group after the stack delete.
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{stack.name}-fn"))
    assert stack.create(_template(stack.name), MarkerQueueParam=marker_url,
                       MarkerQueueArnParam=marker_arn) == "CREATE_COMPLETE", (
        f"the stack did not create: {stack.status()!r}")

    source_queue_url, function_name = stack.outputs()["SourceQueueUrl"], stack.outputs()["FunctionName"]
    esm_uuid = _wait_esm_enabled(lam, function_name, timeout_s=_ESM_ENABLED_TIMEOUT_S)
    filters = lam.get_event_source_mapping(UUID=esm_uuid)["FilterCriteria"]["Filters"]
    patterns = [json.loads(f["Pattern"]) for f in filters]
    assert patterns == [json.loads(_FILTER_PATTERN)], (
        f"GetEventSourceMapping reports FilterCriteria {filters!r}, the template declared {_FILTER_PATTERN!r}"
    )

    # Positive control: a message that matches the filter is delivered and consumed.
    good_id = ctx.unique_name("good-")
    sqs.send_message(QueueUrl=source_queue_url,
                     MessageBody=json.dumps({"kind": "process", "orderId": good_id}))
    latency_s, _ = _latency(lambda: _receive_marker(sqs, marker_url, good_id), budget_s=150.0)

    # Negative: a message the filter excludes is never delivered.
    bad_id = ctx.unique_name("bad-")
    sqs.send_message(QueueUrl=source_queue_url,
                     MessageBody=json.dumps({"kind": "skip", "orderId": bad_id}))
    window_s = max(10.0, 3.0 * latency_s)
    seen = _absent_for(lambda: _drain_markers(sqs, marker_url), window_s)
    assert not any(m.get("orderId") == bad_id for m in seen), (
        f"a marker for the filtered-out message {bad_id!r} arrived within {window_s}s: {seen!r} "
        f"-- the handler ran on a message the FilterCriteria should have excluded"
    )

    # Lambda itself removes a non-matching SQS message once it has evaluated the filter --
    # the queue drains without the function ever running (per the Lambda developer guide).
    _wait_queue_drained(sqs, source_queue_url, timeout_s=90.0)

    role_name = stack.cfn.describe_stack_resource(StackName=stack.name, LogicalResourceId="ExecRole")[
        "StackResourceDetail"]["PhysicalResourceId"]
    assert stack.delete() == 0, f"stack {stack.name} did not reach DELETE_COMPLETE"
    gone = [
        (_error(lambda: lam.get_event_source_mapping(UUID=esm_uuid)),
         ("ResourceNotFoundException", "The resource you requested does not exist.")),
        (_error(lambda: lam.get_function(FunctionName=function_name)),
         ("ResourceNotFoundException",
          f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{function_name}")),
        (_error(lambda: sqs.get_queue_attributes(QueueUrl=source_queue_url)),
         ("AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist.")),
        (_error(lambda: ctx.client("iam").get_role(RoleName=role_name)),
         ("NoSuchEntity", f"The role with name {role_name} cannot be found.")),
    ]
    for got, want in gone:
        assert got == want, f"after the stack delete: expected {want!r}, got {got!r}"


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return str(exc.response["Error"]["Code"]), str(exc.response["Error"].get("Message", ""))
    raise AssertionError(f"the call succeeded; it must be rejected: {result!r}")


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 2.0,
                    budget_s: float = 50.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent."""
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
                raise AssertionError(f"log group {name} still present after {budget_s}s of deletes")
            time.sleep(interval_s)


def _latency(observe, *, budget_s: float = 60.0, poll_s: float = 2.0) -> tuple[float, dict]:
    start = time.monotonic()
    while True:
        result = observe()
        if result is not None:
            return time.monotonic() - start, result
        if time.monotonic() - start > budget_s:
            raise AssertionError(f"the positive control saw nothing in {budget_s}s")
        time.sleep(poll_s)


def _absent_for(observe, window_s: float, *, poll_s: float = 2.0) -> list[dict]:
    deadline = time.monotonic() + window_s
    seen: list[dict] = []
    while time.monotonic() < deadline:
        seen.extend(observe())
        time.sleep(poll_s)
    return seen


def _receive_marker(sqs, marker_url: str, order_id: str) -> dict | None:
    resp = sqs.receive_message(QueueUrl=marker_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
    for msg in resp.get("Messages", []):
        record = json.loads(msg["Body"])
        sqs.delete_message(QueueUrl=marker_url, ReceiptHandle=msg["ReceiptHandle"])
        if record.get("orderId") == order_id:
            return record
    return None


def _drain_markers(sqs, marker_url: str) -> list[dict]:
    resp = sqs.receive_message(QueueUrl=marker_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
    out = []
    for msg in resp.get("Messages", []):
        record = json.loads(msg["Body"])
        sqs.delete_message(QueueUrl=marker_url, ReceiptHandle=msg["ReceiptHandle"])
        out.append(record)
    return out


def _wait_queue_drained(sqs, queue_url: str, *, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        attrs = sqs.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"]
        last = attrs
        if attrs["ApproximateNumberOfMessages"] == "0" and attrs["ApproximateNumberOfMessagesNotVisible"] == "0":
            return
        time.sleep(2.0)
    raise AssertionError(f"source queue did not drain within {timeout_s}s: last attributes {last!r}")


def _delete_queue(sqs, url: str) -> None:
    try:
        sqs.delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "AWS.SimpleQueueService.NonExistentQueue":
            raise


def _wait_esm_enabled(lam, function_name: str, *, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        mappings = lam.list_event_source_mappings(FunctionName=function_name)["EventSourceMappings"]
        assert len(mappings) == 1, f"expected exactly one ESM for {function_name!r}, got {mappings!r}"
        last = mappings[0]
        if last["State"] == "Enabled":
            return last["UUID"]
        time.sleep(2.0)
    raise AssertionError(f"ESM for {function_name!r} did not reach Enabled within {timeout_s}s: "
                         f"last state {last!r}")


def _poll(probe, predicate, *, timeout_s=120.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s. Last: {last!r}")
        time.sleep(interval_s)


class _Stack:
    """One stack under a unique name, its delete registered BEFORE the create."""

    def __init__(self, ctx, tok: str) -> None:
        self.ctx, self.name, self.cfn = ctx, tok, ctx.client("cloudformation")
        self._deleted: int | None = None

    def create(self, body: str, **params: str) -> str:
        self.ctx.on_cleanup(self._delete_net)
        self.cfn.create_stack(
            StackName=self.name, TemplateBody=body, Capabilities=["CAPABILITY_IAM"],
            Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in params.items()])
        return self.wait()

    def status(self) -> str:
        try:
            return self.cfn.describe_stacks(StackName=self.name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if "does not exist" in str(exc):
                return "GONE"
            raise

    def wait(self) -> str:
        return _poll(self.status, lambda s: not s.endswith("_IN_PROGRESS"),
                     timeout_s=_STACK_DEADLINE_S, interval_s=2.0,
                     description=f"stack {self.name} reached a terminal status")

    def outputs(self) -> dict:
        stack = self.cfn.describe_stacks(StackName=self.name)["Stacks"][0]
        return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs") or []}

    def delete(self) -> int:
        if self._deleted is not None:
            return self._deleted
        if self.status() == "GONE":
            self._deleted = 0
            return 0
        self.cfn.delete_stack(StackName=self.name)
        final = _poll(self.status, lambda s: s in ("GONE", "DELETE_FAILED"),
                      timeout_s=_STACK_DEADLINE_S, interval_s=2.0,
                      description=f"stack {self.name} deleted")
        self._deleted = 0 if final == "GONE" else 1
        return self._deleted

    def _delete_net(self) -> None:
        if self.status().endswith("_IN_PROGRESS"):
            self.wait()
        if self.delete() != 0:
            raise AssertionError(f"stack {self.name} did not reach DELETE_COMPLETE")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
