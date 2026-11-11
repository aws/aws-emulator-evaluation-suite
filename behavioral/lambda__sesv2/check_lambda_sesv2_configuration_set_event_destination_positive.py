"""lambda-sesv2-configuration-set-event-destination-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "lambda-sesv2-configuration-set-event-destination-positive"
GROUP = "account-config"
SERVICES = ["lambda", "sesv2"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda whose role grants the create permissions creates a configuration set and
    attaches an SNS event destination to it, verified via get_configuration_set_event_destinations."""
    sesv2 = ctx.client("sesv2")
    sns = ctx.client("sns")

    config_set_name = ctx.unique_name("sim2real-sesv2lam-cfg-")
    dest_name = ctx.unique_name("sim2real-sesv2lam-dest-")
    topic_name = ctx.unique_name("sim2real-sesv2lam-topic-")
    topic_arn = sns.create_topic(Name=topic_name, Tags=[{"Key": "sim2real", "Value": "true"}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    ctx.on_cleanup(lambda: sesv2.delete_configuration_set(ConfigurationSetName=config_set_name))

    role_arn = _create_lambda_role(
        ctx,
        [
            {"Effect": "Allow", "Action": "ses:CreateConfigurationSet", "Resource": "*"},
            {"Effect": "Allow", "Action": "ses:CreateConfigurationSetEventDestination", "Resource": "*"},
            {"Effect": "Allow", "Action": "ses:TagResource", "Resource": "*"},
        ],
    )
    code = '''
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    client = boto3.client("sesv2")
    try:
        client.create_configuration_set(
            ConfigurationSetName=event["config_set"],
            Tags=[{"Key": "sim2real", "Value": "true"}],
        )
        client.create_configuration_set_event_destination(
            ConfigurationSetName=event["config_set"],
            EventDestinationName=event["dest_name"],
            EventDestination={
                "Enabled": True,
                "MatchingEventTypes": ["SEND", "BOUNCE"],
                "SnsDestination": {"TopicArn": event["topic_arn"]},
            },
        )
    except ClientError as exc:
        return {"success": False, "error_code": exc.response["Error"]["Code"]}
    return {"success": True}
'''
    fn_name = _create_lambda_function(ctx, role_arn, code)
    body = _invoke_lambda(
        ctx,
        fn_name,
        {"config_set": config_set_name, "dest_name": dest_name, "topic_arn": topic_arn},
    )
    assert body["success"] is True, body

    resp = sesv2.get_configuration_set_event_destinations(ConfigurationSetName=config_set_name)
    destinations = {d["Name"]: d for d in resp["EventDestinations"]}
    assert dest_name in destinations, f"{dest_name!r} not among {sorted(destinations)}"
    matched = destinations[dest_name]
    assert matched["Enabled"] is True, matched
    assert sorted(matched["MatchingEventTypes"]) == ["BOUNCE", "SEND"], matched["MatchingEventTypes"]
    assert matched["SnsDestination"]["TopicArn"] == topic_arn, matched["SnsDestination"]


def _lambda_zip_bytes(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx, inline_statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sesv2lam-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if inline_statements:
        policy_name = f"{role_name}-policy"
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": inline_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_lambda_function(ctx, role_arn, code):
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-sesv2lam-fn-")
    zip_bytes = _lambda_zip_bytes(code)
    deadline = time.monotonic() + 90
    while True:
        try:
            lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                MemorySize=128,
                Tags={"sim2real": "true"},
            )
            break
        except lam.exceptions.InvalidParameterValueException:
            if time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: _delete_function_log_group(ctx, fn_name))
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    lam.get_waiter("function_active_v2").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return fn_name


def _invoke_lambda(ctx, fn_name, payload):
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=fn_name, Payload=json.dumps(payload).encode("utf-8"))
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation errored: {body}")
    return body


def _delete_function_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates for a function on its first invocation and never
    deletes. Registered before the function's own teardown, so it runs after the function is
    gone; the service can still create the group from logs it delivers a few seconds later, so
    the group must stay absent across two reads 5 s apart. Only an already-absent group is
    tolerated; a group still present after 30 s raises."""
    import time

    from botocore.exceptions import ClientError

    logs = ctx.client("logs")
    group = f"/aws/lambda/{function_name}"

    def present() -> bool:
        found = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
        return any(g["logGroupName"] == group for g in found)

    deadline = time.monotonic() + 30.0
    while True:
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(5.0)
        if not present():
            time.sleep(5.0)
            if not present():
                return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"log group {group} still present 30 s after delete_log_group")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
