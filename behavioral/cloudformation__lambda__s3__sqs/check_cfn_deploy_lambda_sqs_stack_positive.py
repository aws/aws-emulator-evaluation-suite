"""cfn-deploy-lambda-sqs-stack-positive."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-lambda-sqs-stack-positive"

GROUP = "deployment-order"

SERVICES = ["cloudformation", "lambda", "s3", "sqs"]

#: Lambda + SQS + S3, wired by Ref/GetAtt: the function sends its event to the queue and writes
#: it to the bucket under its request id.
_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Description: Lambda + SQS + S3 stack for cross-service integration check

Resources:
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: !Sub 'sim2real-xsvc-cfn-queue-${AWS::StackName}'

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
        - PolicyName: SendToQueue
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - sqs:SendMessage
                Resource: !GetAtt Queue.Arn
        - PolicyName: WriteBucket
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - s3:PutObject
                Resource: !Sub '${Bucket.Arn}/*'
        - PolicyName: BasicExecution
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
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
      Runtime: python3.11
      Handler: index.lambda_handler
      Timeout: 30
      Role: !GetAtt LambdaRole.Arn
      Environment:
        Variables:
          QUEUE_URL: !Ref Queue
          BUCKET: !Ref Bucket
      Code:
        ZipFile: |
          import json, os, boto3
          def lambda_handler(event, context):
              body = json.dumps(event)
              boto3.client('sqs').send_message(QueueUrl=os.environ['QUEUE_URL'], MessageBody=body)
              key = context.aws_request_id
              boto3.client('s3').put_object(Bucket=os.environ['BUCKET'], Key=key, Body=body.encode())
              return {'statusCode': 200, 'key': key}

Outputs:
  FunctionName:
    Value: !Ref LambdaFunction
  QueueUrl:
    Value: !Ref Queue
  QueueArn:
    Value: !GetAtt Queue.Arn
  BucketName:
    Value: !Ref Bucket
  RoleName:
    Value: !Ref LambdaRole
"""


def _msg_body(msg: dict) -> str:
    """Normalize a message body from wait_for_messages — harness may return raw str or pre-parsed dict."""
    raw = msg.get("Body") or msg.get("body", "")
    if isinstance(raw, dict):
        return json.dumps(raw)
    return str(raw)


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
    """Deploy Lambda+SQS via CFN; verify Ref/GetAtt wiring and end-to-end invoke."""
    result = _deploy_cfn(ctx, _TEMPLATE)
    outputs = result["outputs"]
    fn_name = outputs["FunctionName"]
    queue_url = outputs["QueueUrl"]
    bucket = outputs["BucketName"]
    role_name = outputs["RoleName"]
    s3 = ctx.client("s3")
    ctx.on_cleanup(_tolerant(lambda: _empty_bucket(s3, bucket), "NoSuchBucket"))

    # Invoking creates /aws/lambda/<fn>, which the stack does not own and its deletion leaves behind.
    logs = ctx.client("logs")
    ctx.on_cleanup(_tolerant(lambda: logs.delete_log_group(logGroupName=f"/aws/lambda/{fn_name}"),
                             "ResourceNotFoundException"))
    marker = ctx.unique_name("cfn-wired-")
    invoke_result = _invoke_lambda(ctx, fn_name, {"data": marker})
    assert invoke_result["status_code"] == 200, (
        f"Lambda invoke status {invoke_result['status_code']}"
    )
    assert "error" not in invoke_result, (
        f"expected no FunctionError, got {invoke_result.get('error')!r}: {invoke_result!r}"
    )
    key = (invoke_result.get("payload") or {}).get("key")
    assert isinstance(key, str) and key, f"expected the function to return its object key, got {invoke_result!r}"

    messages = _wait_for_messages(ctx, queue_url, expected_count=1, timeout_s=30)
    assert messages, "No messages received in deployed SQS queue"
    body = _msg_body(messages[0])
    assert marker in body, f"Expected {marker!r} in message body, got: {body}"
    stored = s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode()
    assert json.loads(stored) == json.loads(body), (
        f"expected the S3 object to hold the event the queue received, got {stored!r} vs {body!r}"
    )

    iam = ctx.client("iam")
    role = iam.get_role(RoleName=role_name)["Role"]
    principals = [
        st.get("Principal", {}).get("Service")
        for st in role["AssumeRolePolicyDocument"].get("Statement", [])
    ]
    assert "lambda.amazonaws.com" in principals or any(
        isinstance(p, list) and "lambda.amazonaws.com" in p for p in principals
    ), f"expected the role trust to name lambda.amazonaws.com, got {principals!r}"
    fn_role = ctx.client("lambda").get_function_configuration(FunctionName=fn_name)["Role"]
    assert fn_role == role["Arn"], (
        f"expected the function's Role to be the GetAtt-resolved role ARN {role['Arn']!r}, got {fn_role!r}"
    )

    # Tear down in the body: empty the bucket, delete the stack, then prove it and each
    # provisioned resource gone.
    _empty_bucket(s3, bucket)
    name, stack_id = result["stack_name"], result["stack_id"]
    _gone_stack(ctx, name, stack_id)
    cfn = ctx.client("cloudformation")
    _refused(lambda: cfn.describe_stacks(StackName=name), ("ValidationError",), 400,
             f"DescribeStacks {name}")
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
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
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


def _wait_for_messages(ctx, queue_url, expected_count=1, timeout_s=60.0, delete=True):
    """Poll SQS until expected_count messages arrive; return them (raises on timeout)."""
    sqs = ctx.client("sqs")
    messages: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while len(messages) < expected_count and time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=min(10, expected_count - len(messages)),
            WaitTimeSeconds=min(5, remaining),
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            messages.append(
                {
                    "body": body,
                    "message_id": msg["MessageId"],
                    "receipt_handle": msg["ReceiptHandle"],
                    "attributes": msg.get("MessageAttributes", {}),
                }
            )
            if delete:
                sqs.delete_message(
                    QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"]
                )
    if len(messages) < expected_count:
        raise AssertionError(
            f"Expected {expected_count} messages, got {len(messages)} within {timeout_s}s"
        )
    return messages


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
    register delete-stack-and-wait teardown. Returns {stack_name,stack_id,outputs:{k:v}}."""
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

#: Bounded convergence for a delete to reach its terminal not-found answer (the default service
#: class budget); a deadline, never an assertion on elapsed time.
_GONE_S = 120.0


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
    deadline = time.monotonic() + _GONE_S
    while True:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            break
        assert status in ("DELETE_IN_PROGRESS",) or status.endswith("_COMPLETE"), f"stack delete reached {status}"
        assert time.monotonic() < deadline, f"stack still {status} {_GONE_S:.0f}s after DeleteStack"
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
