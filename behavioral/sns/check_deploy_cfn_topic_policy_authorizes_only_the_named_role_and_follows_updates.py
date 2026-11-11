"""deploy-cfn-topic-policy-authorizes-only-the-named-role-and-follows-updates."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-topic-policy-authorizes-only-the-named-role-and-follows-updates"
GROUP = "deploy"
SERVICES = ["sns"]


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _template(granted: str) -> str:
    tags_ = [{"Key": "sim2real", "Value": CHECK}]
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"AWS": {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}},
        "Action": "sts:AssumeRole"}]}
    return json.dumps({
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic", "Properties": {"Tags": tags_}},
            "RoleA": {"Type": "AWS::IAM::Role", "Properties": {"AssumeRolePolicyDocument": trust, "Tags": tags_}},
            "RoleB": {"Type": "AWS::IAM::Role", "Properties": {"AssumeRolePolicyDocument": trust, "Tags": tags_}},
            "TopicPolicy": {
                "Type": "AWS::SNS::TopicPolicy",
                "Properties": {
                    "Topics": [{"Ref": "Topic"}],
                    "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
                        "Sid": "NamedRolePublishes", "Effect": "Allow",
                        "Principal": {"AWS": {"Fn::GetAtt": [granted, "Arn"]}},
                        "Action": "sns:Publish", "Resource": {"Ref": "Topic"}}]},
                },
            },
            "Queue": {"Type": "AWS::SQS::Queue", "Properties": {"Tags": tags_}},
            "QueuePolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "Queue"}],
                    "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
                        "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
                        "Action": "sqs:SendMessage", "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                        "Condition": {"ArnEquals": {"aws:SourceArn": {"Ref": "Topic"}}}}]},
                },
            },
            "Subscription": {
                "Type": "AWS::SNS::Subscription",
                "Properties": {"TopicArn": {"Ref": "Topic"}, "Protocol": "sqs",
                               "Endpoint": {"Fn::GetAtt": ["Queue", "Arn"]}},
            },
        },
        "Outputs": {
            "TopicArn": {"Value": {"Ref": "Topic"}},
            "QueueUrl": {"Value": {"Ref": "Queue"}},
            "RoleAName": {"Value": {"Ref": "RoleA"}},
            "RoleAArn": {"Value": {"Fn::GetAtt": ["RoleA", "Arn"]}},
            "RoleBName": {"Value": {"Ref": "RoleB"}},
            "RoleBArn": {"Value": {"Fn::GetAtt": ["RoleB", "Arn"]}},
        },
    })


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A deployed TopicPolicy lets only the named role publish (the other gets AuthorizationError and
    is never delivered), and a stack update naming the other role flips both verdicts.
    """
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    partition = ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]
    stack = ctx.unique_name("sim2real-behav-sns-cfnpol-")

    out = _create_stack(ctx, cfn, stack, _template("RoleA"))
    topic, queue_url = out["TopicArn"], out["QueueUrl"]
    sns_a = _client_as_role(ctx, "sns", out["RoleAArn"], "sim2real-sns-a")
    sns_b = _client_as_role(ctx, "sns", out["RoleBArn"], "sim2real-sns-b")

    def _denied(role_sns, role_name: str, session: str, body: str) -> None:
        code, message = _error(lambda: role_sns.publish(TopicArn=topic, Message=body))
        assumed = f"arn:{partition}:sts::{ctx.account}:assumed-role/{role_name}/{session}"
        expected = (f"User: {assumed} is not authorized to perform: SNS:Publish on resource: {topic} "
                    "because no identity-based policy allows the SNS:Publish action")
        assert (code, message) == ("AuthorizationError", expected), (
            f"the role the deployed policy does not name must be refused with AuthorizationError "
            f"{expected!r}; got {code!r} {message!r}")

    granted_1 = ctx.unique_name("sim2real-a-granted-")
    _until_authorized(lambda: sns_a.publish(TopicArn=topic, Message=granted_1))
    denied_1 = ctx.unique_name("sim2real-b-denied-")
    _denied(sns_b, out["RoleBName"], "sim2real-sns-b", denied_1)
    got = _drain_until(sqs, queue_url, {granted_1}, 60)
    assert granted_1 in got, f"the named role's Publish never reached the stack's subscriber; got {got!r}"

    _update_stack(cfn, stack, _template("RoleB"))
    granted_2 = ctx.unique_name("sim2real-b-granted-")
    _until_authorized(lambda: sns_b.publish(TopicArn=topic, Message=granted_2))
    denied_2 = ctx.unique_name("sim2real-a-denied-")
    _until_refused(lambda: sns_a.publish(TopicArn=topic, Message=ctx.unique_name("sim2real-a-probe-")))
    _denied(sns_a, out["RoleAName"], "sim2real-sns-a", denied_2)
    got += _drain_until(sqs, queue_url, {granted_2}, 60)
    assert granted_2 in got, f"after the update the newly named role's Publish never arrived; got {got!r}"
    assert denied_1 not in got and denied_2 not in got, (
        "a Publish the deployed topic policy refused was delivered to the subscriber anyway")


def _create_stack(ctx, cfn, name: str, body: str) -> dict:
    def _cleanup():
        cfn.delete_stack(StackName=name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    cfn.create_stack(StackName=name, TemplateBody=body, Capabilities=["CAPABILITY_IAM"],
                     Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    desc = cfn.describe_stacks(StackName=name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


def _update_stack(cfn, name: str, body: str) -> None:
    cfn.update_stack(StackName=name, TemplateBody=body, Capabilities=["CAPABILITY_IAM"])
    cfn.get_waiter("stack_update_complete").wait(
        StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})


def _client_as_role(ctx, service: str, role_arn: str, session: str):
    sts = ctx.client("sts")
    deadline = time.monotonic() + 90
    while True:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=session)["Credentials"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    return ctx.client(service, creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })


def _until_authorized(fn):
    """Retry AuthorizationError only while a just-written grant propagates."""
    deadline = time.monotonic() + 120
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AuthorizationError" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _until_refused(fn) -> None:
    """Call ``fn`` until it raises AuthorizationError (a just-revoked grant can linger while the
    policy change propagates); a grant that is never revoked fails loudly."""
    deadline = time.monotonic() + 120
    while True:
        try:
            fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AuthorizationError":
                return
            raise
        assert time.monotonic() < deadline, "the revoked role kept publishing after the stack update"
        time.sleep(3)


def _drain_until(sqs, url: str, wanted: set[str], timeout_s: float) -> list[str]:
    out: list[str] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not wanted <= set(out):
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            out.append(json.loads(msg["Body"])["Message"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
