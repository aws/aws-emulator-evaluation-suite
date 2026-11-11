"""cfn-deploy-lambda-sqs-stack-prefixed-json-objects-and-attributed-messages."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-lambda-sqs-stack-prefixed-json-objects-and-attributed-messages"

GROUP = "deployment-order"

SERVICES = ["cloudformation", "lambda", "s3", "sqs"]

#: Lambda + SQS + S3, wired by Ref/GetAtt and environment: the function sends each event to the
#: queue with a message attribute and writes it to the bucket under a prefix as JSON.
_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Description: Lambda + SQS + S3 stack, prefixed JSON objects and attributed messages

Parameters:
  KeyPrefix:
    Type: String

Resources:
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: !Sub 'sim2real-xsvc-cfn-queue-${AWS::StackName}'
      MessageRetentionPeriod: 600

  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub 'sim2real-xsvc-cfn-bkt-${AWS::StackName}'

  LambdaRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Sub 'sim2real-xsvc-cfn-role-${AWS::StackName}'
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: SendAndWrite
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action: sqs:SendMessage
                Resource: !GetAtt Queue.Arn
              - Effect: Allow
                Action: s3:PutObject
                Resource: !Sub '${Bucket.Arn}/${KeyPrefix}/*'
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: '*'

  LambdaFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Sub 'sim2real-xsvc-cfn-fn-${AWS::StackName}'
      Runtime: python3.12
      Handler: index.handler
      Timeout: 30
      MemorySize: 256
      Role: !GetAtt LambdaRole.Arn
      Environment:
        Variables:
          QUEUE_URL: !Ref Queue
          BUCKET: !Ref Bucket
          KEY_PREFIX: !Ref KeyPrefix
      Code:
        ZipFile: |
          import json, os, boto3
          def handler(event, context):
              body = json.dumps(event, ensure_ascii=False, sort_keys=True)
              boto3.client('sqs').send_message(
                  QueueUrl=os.environ['QUEUE_URL'], MessageBody=body,
                  MessageAttributes={'seq': {'DataType': 'Number', 'StringValue': str(event['seq'])}})
              key = os.environ['KEY_PREFIX'] + '/' + str(event['seq']) + '-' + context.aws_request_id + '.json'
              boto3.client('s3').put_object(Bucket=os.environ['BUCKET'], Key=key, Body=body.encode('utf-8'),
                                            ContentType='application/json')
              return {'key': key, 'bytes': len(body.encode('utf-8'))}

Outputs:
  FunctionName:
    Value: !Ref LambdaFunction
  QueueUrl:
    Value: !Ref Queue
  BucketName:
    Value: !Ref Bucket
  RoleName:
    Value: !Ref LambdaRole
"""


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Three invokes of a stack-deployed function with multibyte payloads each reach the stack's
    queue with a Number attribute and the stack's bucket under the parameter-given prefix as JSON:
    three distinct messages and exactly three objects, byte-equal; DeleteStack then removes every resource.
    """
    prefix = "in/" + ctx.unique_name("p")
    result = _deploy_cfn(ctx, _TEMPLATE, parameters={"KeyPrefix": prefix})
    outputs = result["outputs"]
    fn_name, queue_url, bucket = outputs["FunctionName"], outputs["QueueUrl"], outputs["BucketName"]
    role_name = outputs["RoleName"]
    s3 = ctx.client("s3")
    ctx.on_cleanup(_tolerant(lambda: _empty_bucket(s3, bucket), "NoSuchBucket"))
    logs = ctx.client("logs")
    ctx.on_cleanup(_tolerant(lambda: logs.delete_log_group(logGroupName=f"/aws/lambda/{fn_name}"),
                             "ResourceNotFoundException"))

    events = [{"seq": n, "text": f"ünïcødé-{n}-" + "雪" * (n * 7), "nested": {"n": [n] * n}} for n in (3, 1, 2)]
    keys = {}
    for event in events:
        out = _invoke_lambda(ctx, fn_name, event)
        assert out["status_code"] == 200 and "error" not in out, f"invoke {event['seq']}: {out!r}"
        key = out["payload"]["key"]
        assert key.startswith(f"{prefix}/{event['seq']}-") and key.endswith(".json"), f"object key {key!r}"
        canonical = json.dumps(event, ensure_ascii=False, sort_keys=True)
        assert out["payload"]["bytes"] == len(canonical.encode()), out
        keys[event["seq"]] = (key, canonical)

    sqs = ctx.client("sqs")
    # A standard queue delivers at least once, so a redelivery repeats a MessageId with the same
    # content; deliveries are keyed by MessageId and each id must be one of the three sends.
    by_id = {}
    deadline = time.monotonic() + 30
    while len(by_id) < 3 and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
                                   MessageAttributeNames=["All"])
        for msg in resp.get("Messages", []):
            attr = msg.get("MessageAttributes", {}).get("seq", {})
            seen = (attr.get("DataType"), attr.get("StringValue"), msg["Body"])
            assert by_id.setdefault(msg["MessageId"], seen) == seen, (
                f"a redelivery of {msg['MessageId']} must carry the same content: {by_id[msg['MessageId']]!r} vs {seen!r}"
            )
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    want = sorted(("Number", str(s), c) for s, (_, c) in keys.items())
    got = sorted(by_id.values())
    assert got == want, (
        f"the queue's distinct MessageIds must carry exactly the three events, each with its Number seq "
        f"attribute, and nothing else: expected {want!r}, got {got!r}"
    )
    listed = sorted(o["Key"] for o in _paged(s3, "list_objects_v2", "Contents", Bucket=bucket, Prefix=prefix + "/"))
    assert listed == sorted(k for k, _ in keys.values()), f"objects under {prefix}/: {listed!r}"
    for key, canonical in keys.values():
        obj = s3.get_object(Bucket=bucket, Key=key)
        assert obj["ContentType"] == "application/json", f"{key} ContentType {obj['ContentType']!r}"
        assert obj["Body"].read() == canonical.encode(), f"{key} must hold the exact UTF-8 bytes of its event"

    fn_role = ctx.client("lambda").get_function_configuration(FunctionName=fn_name)
    assert fn_role["Environment"]["Variables"]["KEY_PREFIX"] == prefix, fn_role["Environment"]
    assert fn_role["Role"] == ctx.client("iam").get_role(RoleName=role_name)["Role"]["Arn"], fn_role["Role"]

    _empty_bucket(s3, bucket)
    name, stack_id = result["stack_name"], result["stack_id"]
    _gone_stack(ctx, name, stack_id)
    cfn = ctx.client("cloudformation")
    _refused(lambda: cfn.describe_stacks(StackName=name), ("ValidationError",), 400, f"DescribeStacks {name}")
    _proved_lambda_gone(ctx, fn_name)
    _proved_role_gone(ctx, role_name)
    _proved_queue_gone(ctx, queue_url.rstrip("/").split("/")[-1], queue_url)
    _proved_bucket_gone(ctx, bucket)


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(
    probe, predicate, *, timeout_s=40.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _invoke_lambda(ctx, name: str, payload: dict | None = None) -> dict[str, Any]:
    """Invoke a Lambda synchronously; return {status_code[, error], payload|payload_raw}."""
    resp = ctx.client("lambda").invoke(
        FunctionName=name,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload or {}).encode(),
    )
    body = resp["Payload"].read()
    result: dict[str, Any] = {"status_code": resp["StatusCode"]}
    if resp.get("FunctionError"):
        result["error"] = resp["FunctionError"]
    try:
        result["payload"] = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        result["payload_raw"] = body.decode("utf-8", errors="replace")
    return result


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE; only a stack that no longer exists counts as gone."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if "does not exist" not in exc.response["Error"].get("Message", ""):
                raise
            return "GONE"

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
    """Deploy a CloudFormation stack (template body str or Path); wait for CREATE_COMPLETE;
    register delete-stack-and-wait teardown. Returns {stack_name,stack_id,outputs:{k:v}}.
    """
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


#: A valid template for the UpdateStack-on-a-deleted-stack beat: with a template body the refusal is
#: the not-found ValidationError ``Stack [<name>] does not exist`` (a missing template is refused
#: for that reason first on some targets).
_GONE_TEMPLATE = '{"Resources": {"Gone": {"Type": "AWS::CloudFormation::WaitConditionHandle"}}}'

#: Bounded convergence for a deleted resource to reach its terminal not-found answer, a read
#: AWS answers at once; a deadline, never an assertion on elapsed time.
_GONE_S = 40.0

#: Bound for the DeleteStack wait itself: a stack delete takes its recorded time on AWS.
_STACK_DELETE_S = 120.0


def _err(exc: ClientError) -> tuple[str, int, str]:
    """(code, HTTP status, message) of a ClientError."""
    e = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return e.get("Code") or "", status, e.get("Message") or e.get("message") or ""


def _refused(fn, codes: tuple[str, ...], status: int, what: str, *, exact: bool = False) -> None:
    """``fn()`` must fail with one of ``codes`` in the HTTP class of ``status`` (exactly ``status`` when ``exact``), a non-empty message."""
    try:
        fn()
    except ClientError as exc:
        code, got, msg = _err(exc)
        want = status if exact else f"{status // 100}xx"
        in_class = isinstance(got, int) and (got == status if exact else got // 100 == status // 100)
        assert code in codes and in_class, (
            f"{what}: expected {'/'.join(codes)} HTTP {want}, got {code!r} HTTP {got!r}: {msg[:150]!r}"
        )
        assert msg.strip(), f"{what}: {code} carries an empty message"
        return
    raise AssertionError(f"{what}: expected {'/'.join(codes)} HTTP {status}, the call succeeded")


def _poll_refused(fn, codes, status, what, timeout_s: float = _GONE_S, exact: bool = False) -> None:
    """Poll ``fn`` until it reaches the terminal not-found answer, then grade it with ``_refused``.

    A success while the delete converges is retried; any other error fails at once.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            code, _, _ = _err(exc)
            if code in codes:
                _refused(fn, codes, status, what, exact=exact)
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: still readable {timeout_s:.0f}s after the delete")
        time.sleep(1.0)


def _tolerant(fn, *codes: str):
    """A teardown that ignores only the given not-found codes (the body already deleted it)."""

    def run() -> None:
        try:
            fn()
        except ClientError as exc:
            if _err(exc)[0] not in codes:
                raise

    return run


def _paged(client, op: str, key: str, **kw) -> list:
    """Every element of ``key`` across all pages of ``op``."""
    out: list = []
    for page in client.get_paginator(op).paginate(**kw):
        out.extend(page.get(key, []))
    return out


def _gone_stack(ctx, name: str, stack_id: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + _STACK_DELETE_S
    while True:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            break
        assert status in ("DELETE_IN_PROGRESS",) or status.endswith("_COMPLETE"), f"stack delete reached {status}"
        assert time.monotonic() < deadline, f"stack still {status} {_STACK_DELETE_S:.0f}s after DeleteStack"
        time.sleep(2.0)
    active = [s for s in _paged(cfn, "list_stacks", "StackSummaries") if s["StackName"] == name and s["StackStatus"] != "DELETE_COMPLETE"]
    assert not active, f"ListStacks still lists {name} as {active[0]['StackStatus']}"
    _refused(lambda: cfn.update_stack(StackName=name, TemplateBody=_GONE_TEMPLATE), ("ValidationError",), 400, f"UpdateStack {name}")


# ---- Proofs for stack-provisioned resources (CloudFormation deleted them) -------------------------
def _empty_bucket(s3, bucket: str) -> None:
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        objs = [{"Key": o["Key"], "VersionId": o["VersionId"]} for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs, "Quiet": True})


def _proved_lambda_gone(ctx, name: str) -> None:
    lam = ctx.client("lambda")
    nf = ("ResourceNotFoundException",)
    _poll_refused(lambda: lam.get_function(FunctionName=name), nf, 404, f"GetFunction {name}")
    listed = {f["FunctionName"] for f in _paged(lam, "list_functions", "Functions")}
    assert name not in listed, f"ListFunctions still lists deleted function {name}"
    # Invoke keeps reaching a just-deleted function for a while on AWS, so it converges like GetFunction.
    _poll_refused(lambda: lam.invoke(FunctionName=name, Payload=b"{}"), nf, 404, f"Invoke {name}")


def _proved_role_gone(ctx, name: str) -> None:
    iam = ctx.client("iam")
    nf = ("NoSuchEntity",)
    _poll_refused(lambda: iam.get_role(RoleName=name), nf, 404, f"GetRole {name}")
    listed = {r["RoleName"] for r in _paged(iam, "list_roles", "Roles", PathPrefix="/")}
    assert name not in listed, f"ListRoles still lists deleted role {name}"
    doc = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:GetQueueUrl","Resource":"*"}]}'
    _refused(
        lambda: iam.put_role_policy(RoleName=name, PolicyName="gone", PolicyDocument=doc),
        nf, 404, f"PutRolePolicy {name}",
    )


_SQS_NF = ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist")


def _proved_queue_gone(ctx, name: str, url: str) -> None:
    sqs = ctx.client("sqs")
    # AWS documents up to 60 s for a deleted queue to stop answering.
    _poll_refused(lambda: sqs.get_queue_url(QueueName=name), _SQS_NF, 400, f"GetQueueUrl {name}")
    listed = sqs.list_queues(QueueNamePrefix=name).get("QueueUrls", [])
    assert not [u for u in listed if u.rstrip("/").split("/")[-1] == name], (
        f"ListQueues still lists deleted queue {name}"
    )
    _refused(lambda: sqs.send_message(QueueUrl=url, MessageBody="gone"), _SQS_NF, 400, f"SendMessage {name}")


def _proved_bucket_gone(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    # HeadBucket has no body: the code is the bare status.
    _poll_refused(lambda: s3.head_bucket(Bucket=bucket), ("404", "NoSuchBucket", "NotFound"), 404, f"HeadBucket {bucket}", exact=True)
    names = {b["Name"] for b in s3.list_buckets(Prefix=bucket).get("Buckets", [])}
    assert bucket not in names, f"ListBuckets still lists deleted bucket {bucket}"
    _refused(lambda: s3.put_object(Bucket=bucket, Key="gone", Body=b"x"), ("NoSuchBucket",), 404, f"PutObject {bucket}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
