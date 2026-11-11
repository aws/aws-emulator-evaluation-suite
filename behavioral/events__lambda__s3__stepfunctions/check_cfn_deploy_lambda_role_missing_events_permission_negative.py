"""cfn-deploy-lambda-role-missing-events-permission-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-lambda-role-missing-events-permission-negative"
GROUP = "overly-permissive"
SERVICES = ["events", "lambda", "s3", "stepfunctions"]


@tags("axis:negative-delivery", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda whose role lacks events:PutEvents gets AccessDeniedException and its event never
    reaches the downstream target; once the permission is granted, the same invocation's event
    triggers the target."""
    emitter_code = (
        "import boto3, json, os\n"
        "from botocore.exceptions import ClientError\n"
        "events = boto3.client('events')\n"
        "def handler(event, context):\n"
        "    marker = event.get('marker', 'none')\n"
        "    try:\n"
        "        events.put_events(Entries=[{\n"
        "            'Source': 'custom.negevents',\n"
        "            'DetailType': 'NegEventsTest',\n"
        "            'Detail': json.dumps({'marker': marker}),\n"
        "        }])\n"
        "        return {'ok': True}\n"
        "    except ClientError as e:\n"
        "        return {'ok': False, 'error_code': e.response['Error']['Code']}\n"
    )
    target_code = (
        "import boto3, os\n"
        "s3 = boto3.client('s3')\n"
        "def handler(event, context):\n"
        "    marker = event.get('detail', {}).get('marker', 'none')\n"
        "    s3.put_object(Bucket=os.environ['BUCKET_NAME'],\n"
        "                  Key=f'target-marker-{marker}.txt', Body=marker.encode())\n"
        "    return {'ok': True}\n"
    )

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "MarkerBucket": {"Type": "AWS::S3::Bucket"},
            "EmitterRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                    # Deliberately NO events:PutEvents — that omission is what this check tests.
                    "Policies": [{
                        "PolicyName": "logs-only",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                                "Resource": "*",
                            }],
                        },
                    }],
                },
            },
            "EmitterFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["EmitterRole", "Arn"]},
                    "Timeout": 30,
                    "Code": {"ZipFile": emitter_code},
                },
            },
            "TargetRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                    "Policies": [{
                        "PolicyName": "put-marker",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": ["s3:PutObject"],
                                    "Resource": {"Fn::Sub": "${MarkerBucket.Arn}/*"},
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                                    "Resource": "*",
                                },
                            ],
                        },
                    }],
                },
            },
            "TargetFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["TargetRole", "Arn"]},
                    "Timeout": 30,
                    "Code": {"ZipFile": target_code},
                    "Environment": {"Variables": {"BUCKET_NAME": {"Ref": "MarkerBucket"}}},
                },
            },
            "NegEventsRule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "EventPattern": {
                        "source": ["custom.negevents"],
                        "detail-type": ["NegEventsTest"],
                    },
                    "Targets": [{"Id": "TargetLambda", "Arn": {"Fn::GetAtt": ["TargetFunction", "Arn"]}}],
                },
            },
            "TargetInvokePermission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "Action": "lambda:InvokeFunction",
                    "FunctionName": {"Ref": "TargetFunction"},
                    "Principal": "events.amazonaws.com",
                    "SourceArn": {"Fn::GetAtt": ["NegEventsRule", "Arn"]},
                },
            },
        },
        "Outputs": {
            "BucketName": {"Value": {"Ref": "MarkerBucket"}},
            "EmitterFunctionName": {"Value": {"Ref": "EmitterFunction"}},
            "EmitterRoleName": {"Value": {"Ref": "EmitterRole"}},
        },
    }

    result = _deploy_cfn(ctx, json.dumps(template))
    bucket = result["outputs"]["BucketName"]
    emitter_name = result["outputs"]["EmitterFunctionName"]
    emitter_role = result["outputs"]["EmitterRoleName"]

    lam = ctx.client("lambda")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    events = ctx.client("events")

    # This check writes marker objects into MarkerBucket, and CloudFormation's AWS::S3::Bucket
    # can never delete a non-empty bucket -- it fails DELETE_FAILED and strands both the bucket
    # and the stack. Registered after _deploy_cfn's own on_cleanup, so LIFO runs this first.
    ctx.on_cleanup(lambda: _empty_bucket(s3, bucket))

    def _target_marker_present(marker):
        try:
            return s3.get_object(Bucket=bucket, Key=f"target-marker-{marker}.txt")["Body"].read().decode()
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchKey":
                return None
            raise

    # Calibration / positive control: put the event directly onto the default bus, bypassing
    # the emitter's role entirely, to prove the rule -> target-permission -> target-function ->
    # S3-write wiring itself works, and to measure how long delivery takes right now so the
    # later absence window can be judged against a real latency instead of a guessed one.
    calib_marker = ctx.unique_name("negevents-calib-")
    t_calib = time.monotonic()
    events.put_events(Entries=[{
        "Source": "custom.negevents",
        "DetailType": "NegEventsTest",
        "Detail": json.dumps({"marker": calib_marker}),
    }])
    calib_body = _poll_until(
        lambda: _target_marker_present(calib_marker),
        lambda b: b == calib_marker,
        timeout_s=90.0,
        interval_s=5.0,
        description="calibration: directly-put event reaching the target lambda via the rule",
    )
    latency_s = time.monotonic() - t_calib
    assert calib_body == calib_marker, (
        f"calibration barrier failed: expected {calib_marker!r} at the target, got {calib_body!r} -- "
        "the rule/target wiring is broken on its own, so an absence measured against the emitter "
        "role afterward would prove nothing"
    )

    marker1 = ctx.unique_name("negevents-")
    resp1 = lam.invoke(
        FunctionName=emitter_name,
        InvocationType="RequestResponse",
        Payload=json.dumps({"marker": marker1}).encode(),
    )
    payload1 = json.loads(resp1["Payload"].read())
    assert payload1["ok"] is False, f"expected the emitter to report failure, got {payload1!r}"
    assert payload1["error_code"] == "AccessDeniedException", (
        f"expected AccessDeniedException from PutEvents, got {payload1.get('error_code')!r}"
    )

    # Absence must hold for at least 3x the latency the SAME rule just needed for a real event,
    # sampled repeatedly rather than slept through once (a fixed sleep would score a correct but
    # slower target as blocked, and would not catch a late leak past a single sample point).
    window_s = min(max(3.0 * latency_s, 15.0), 150.0)
    interval_s = min(10.0, window_s / 4)
    deadline = time.monotonic() + window_s
    samples = 0
    while time.monotonic() < deadline:
        leaked = _target_marker_present(marker1)
        assert leaked is None, (
            f"target lambda was invoked despite the emitter lacking events:PutEvents: {leaked!r}"
        )
        samples += 1
        time.sleep(interval_s)
    assert samples >= 3, f"the absence window took too few samples to be meaningful: {samples}"

    # Fix: grant events:PutEvents on the emitter role.
    iam.put_role_policy(
        RoleName=emitter_role,
        PolicyName="allow-put-events",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "events:PutEvents", "Resource": "*"}],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=emitter_role, PolicyName="allow-put-events"))

    marker2 = ctx.unique_name("negevents-fixed-")

    def _invoke_and_check():
        resp = lam.invoke(
            FunctionName=emitter_name,
            InvocationType="RequestResponse",
            Payload=json.dumps({"marker": marker2}).encode(),
        )
        payload = json.loads(resp["Payload"].read())
        if payload.get("ok") is not True:
            # IAM policy propagation can lag behind put_role_policy; keep polling
            # instead of failing hard on a transient AccessDeniedException.
            return None
        return _target_marker_present(marker2)

    body = _poll_until(
        _invoke_and_check,
        lambda b: b == marker2,
        timeout_s=120,
        interval_s=5.0,
        description="positive control: downstream target invoked once permission is granted",
    )
    assert body == marker2, f"expected {marker2!r} at the target after granting events:PutEvents, got {body!r}"


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _empty_bucket(s3, bucket: str) -> None:
    while True:
        page = s3.list_objects_v2(Bucket=bucket)
        contents = page.get("Contents", [])
        if not contents:
            return
        failed = s3.delete_objects(
            Bucket=bucket,
            Delete={"Objects": [{"Key": o["Key"]} for o in contents]},
        ).get("Errors")
        if failed:
            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        if not page.get("IsTruncated"):
            return


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
            ):
                raise
            return 'GONE'

    # A delete can fail on a dependency that clears moments later; retry it twice.
    for _ in range(3):
        cfn.delete_stack(StackName=stack_name)
        status = _poll_until(
            _status,
            lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
            timeout_s=300,
            interval_s=5.0,
            description=f"delete stack {stack_name}",
        )
        if status != "DELETE_FAILED":
            return
        time.sleep(15.0)
    raise AssertionError(f"stack {stack_name} is still DELETE_FAILED after three deletes")


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
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
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
