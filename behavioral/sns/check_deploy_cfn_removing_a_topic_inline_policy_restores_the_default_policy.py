"""deploy-cfn-removing-a-topic-inline-policy-restores-the-default-policy."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-removing-a-topic-inline-policy-restores-the-default-policy"
GROUP = "deploy"
SERVICES = ["sns"]

_SID = "StackRolePublishes"


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _template(with_policy: bool) -> str:
    tags_ = [{"Key": "sim2real", "Value": CHECK}]
    resources = {
        "Topic": {"Type": "AWS::SNS::Topic", "Properties": {"Tags": tags_}},
        "Role": {"Type": "AWS::IAM::Role", "Properties": {"Tags": tags_, "AssumeRolePolicyDocument": {
            "Version": "2012-10-17", "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}},
                "Action": "sts:AssumeRole"}]}}},
    }
    if with_policy:
        resources["InlinePolicy"] = {
            "Type": "AWS::SNS::TopicInlinePolicy",
            "Properties": {
                "TopicArn": {"Ref": "Topic"},
                "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Sid": _SID, "Effect": "Allow",
                    "Principal": {"AWS": {"Fn::GetAtt": ["Role", "Arn"]}},
                    "Action": "sns:Publish", "Resource": {"Ref": "Topic"}}]},
            },
        }
    return json.dumps({"Resources": resources, "Outputs": {
        "TopicArn": {"Value": {"Ref": "Topic"}},
        "RoleName": {"Value": {"Ref": "Role"}},
        "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
    }})


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:deploy", "concern:negative-classes",
      "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """While a TopicInlinePolicy is deployed it is the topic's policy and its role publishes; removing
    it by stack update restores the default policy and the role gets AuthorizationError.
    """
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    partition = ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]
    stack = ctx.unique_name("sim2real-behav-sns-cfninl-")
    out = _create_stack(ctx, cfn, stack, _template(True))
    topic = out["TopicArn"]

    sids = _sids(sns, topic)
    assert sids == [_SID], f"while the inline policy is deployed the topic policy carries statements {sids!r}"
    role_sns = _client_as_role(ctx, "sns", out["RoleArn"], "sim2real-sns-inl")
    mid = _until_authorized(lambda: role_sns.publish(TopicArn=topic, Message="sim2real-allowed")["MessageId"])
    assert mid, "the role the inline policy names must be able to publish"

    _update_stack(cfn, stack, _template(False))
    deadline = time.monotonic() + 60
    while (sids := _sids(sns, topic)) != ["__default_statement_ID"]:
        assert time.monotonic() < deadline, (
            f"after the inline policy was removed the topic policy carries statements {sids!r}, "
            "not the default statement")
        time.sleep(2)
    _until_refused(lambda: role_sns.publish(TopicArn=topic, Message=ctx.unique_name("sim2real-probe-")))
    code, message = _error(lambda: role_sns.publish(TopicArn=topic, Message="sim2real-denied"))
    assumed = f"arn:{partition}:sts::{ctx.account}:assumed-role/{out['RoleName']}/sim2real-sns-inl"
    expected = (f"User: {assumed} is not authorized to perform: SNS:Publish on resource: {topic} "
                "because no identity-based policy allows the SNS:Publish action")
    assert (code, message) == ("AuthorizationError", expected), (
        f"with the default policy back, the role must be refused with AuthorizationError {expected!r}; "
        f"got {code!r} {message!r}")


def _sids(sns, topic: str) -> list[str]:
    doc = json.loads(sns.get_topic_attributes(TopicArn=topic)["Attributes"]["Policy"])
    return sorted(s.get("Sid", "") for s in doc["Statement"])


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
