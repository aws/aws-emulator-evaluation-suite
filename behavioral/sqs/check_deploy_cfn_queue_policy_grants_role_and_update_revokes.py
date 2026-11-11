"""deploy-cfn-queue-policy-grants-role-and-update-revokes."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-queue-policy-grants-role-and-update-revokes"
GROUP = "deploy"
SERVICES = ["sqs"]

SESSION = "sim2real-behav-cfn-grantee"


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack QueuePolicy on two queues (one statement per queue, as SQS requires) lets a role send
    to both; a stack update removing only the policy clears Policy on both and the role becomes
    AccessDenied, while the queues and already-sent messages survive.
    """
    sqs = ctx.client("sqs")
    cfn = ctx.client("cloudformation")
    account = ctx.client("sts").get_caller_identity()["Account"]

    role_name, role_arn = _create_role(ctx, account)
    caller = f"arn:aws:sts::{account}:assumed-role/{role_name}/{SESSION}"
    names = {"A": ctx.unique_name("sim2real-behav-cfnpol-a-"), "B": ctx.unique_name("sim2real-behav-cfnpol-b-")}

    stack = ctx.unique_name("sim2real-behav-cfnpol-")
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))
    cfn.create_stack(StackName=stack, TemplateBody=json.dumps(_template(names, with_policy=True)),
                     Parameters=[{"ParameterKey": "GranteeArn", "ParameterValue": role_arn}],
                     Tags=[{"Key": "sim2real", "Value": CHECK}])
    _wait_stack(cfn, stack, "CREATE_COMPLETE")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in cfn.describe_stacks(StackName=stack)["Stacks"][0]["Outputs"]}
    urls = {k: outputs[f"Url{k}"] for k in names}
    arns = {k: f"arn:aws:sqs:{ctx.region}:{account}:{names[k]}" for k in names}

    for k in names:
        stored = json.loads(sqs.get_queue_attributes(QueueUrl=urls[k], AttributeNames=["Policy"])["Attributes"]["Policy"])
        assert all(st["Condition"] == {"ArnEquals": {"aws:PrincipalArn": role_arn}} for st in stored["Statement"]), (
            f"queue {k} policy {stored!r}"
        )
        assert sorted(st["Resource"] for st in stored["Statement"]) == sorted(arns.values()), (
            f"queue {k} should carry the one shared document naming both queues, got {stored!r}"
        )

    role_sqs = ctx.client("sqs", creds=_assume(ctx, role_arn))
    for k in names:
        _until_allowed(lambda k=k: role_sqs.send_message(QueueUrl=urls[k], MessageBody=f"deployed-grant-{k}"))

    cfn.update_stack(StackName=stack, TemplateBody=json.dumps(_template(names, with_policy=False)),
                     Parameters=[{"ParameterKey": "GranteeArn", "ParameterValue": role_arn}])
    _wait_stack(cfn, stack, "UPDATE_COMPLETE")

    for k in names:
        attrs = sqs.get_queue_attributes(QueueUrl=urls[k], AttributeNames=["All"])["Attributes"]
        assert "Policy" not in attrs, f"queue {k} still has a Policy after the update: {attrs.get('Policy')!r}"
        err = _poll(lambda k=k: _send_outcome(role_sqs, urls[k], f"after-revoke-{k}"),
                    lambda e: e["Code"] == "AccessDenied", timeout_s=300.0, interval_s=5.0)
        assert err["Message"] == _denied(caller, "sendmessage", arns[k]), f"queue {k}: got {err['Message']!r}"

    for k in names:
        bodies = _drain(sqs, urls[k])
        assert f"deployed-grant-{k}" in bodies, f"queue {k} lost the message sent before the update: {bodies!r}"
        assert all(b in (f"deployed-grant-{k}", f"after-revoke-{k}") for b in bodies), f"queue {k} held {bodies!r}"


def _template(names, *, with_policy):
    resources = {
        "QueueA": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": names["A"]}},
        "QueueB": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": names["B"]}},
    }
    if with_policy:
        resources["SharedPolicy"] = {
            "Type": "AWS::SQS::QueuePolicy",
            "Properties": {
                "Queues": [{"Ref": "QueueA"}, {"Ref": "QueueB"}],
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": f"grantee{k}",
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "sqs:SendMessage",
                            "Resource": {"Fn::GetAtt": [f"Queue{k}", "Arn"]},
                            "Condition": {"ArnEquals": {"aws:PrincipalArn": {"Ref": "GranteeArn"}}},
                        }
                        for k in ("A", "B")
                    ],
                },
            },
        }
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"GranteeArn": {"Type": "String"}},
        "Resources": resources,
        "Outputs": {"UrlA": {"Value": {"Ref": "QueueA"}}, "UrlB": {"Value": {"Ref": "QueueB"}}},
    }


def _send_outcome(client, url, body):
    """The Error dict of a send, or a marker while the revocation has not propagated yet."""
    try:
        client.send_message(QueueUrl=url, MessageBody=body)
    except ClientError as exc:
        return exc.response["Error"]
    return {"Code": "<accepted>", "Message": ""}


def _drain(sqs, url, timeout_s=20.0):
    bodies = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", [])
        if not msgs and bodies:
            break
        for m in msgs:
            bodies.append(m["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    return bodies


def _wait_stack(cfn, stack, want, timeout_s=600.0):
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        if status == want:
            return
        if not status.endswith("_IN_PROGRESS") or time.monotonic() > deadline:
            events = cfn.describe_stack_events(StackName=stack)["StackEvents"]
            reasons = [(e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
                       for e in events if e["ResourceStatus"].endswith("_FAILED")]
            raise AssertionError(f"stack reached {status!r}, expected {want!r}; failed events {reasons!r}")
        time.sleep(5)


def _delete_stack(cfn, stack):
    """Delete the stack and wait; a stack that never got created is already gone."""
    try:
        cfn.describe_stacks(StackName=stack)
    except ClientError as exc:
        if "does not exist" in exc.response["Error"]["Message"]:
            return
        raise
    cfn.delete_stack(StackName=stack)
    cfn.get_waiter("stack_delete_complete").wait(StackName=stack, WaiterConfig={"Delay": 2, "MaxAttempts": 300})


def _denied(caller, action, queue_arn):
    return (
        f"User: {caller} is not authorized to perform: sqs:{action} on resource: {queue_arn} "
        f"because no identity-based policy allows the sqs:{action} action"
    )


def _error(fn):
    """The Error dict ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _receive_one(sqs, url, *, visibility, timeout_s=60.0):
    def probe():
        msgs = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2, VisibilityTimeout=visibility,
            AttributeNames=["ApproximateReceiveCount"],
        ).get("Messages", [])
        return msgs[0] if msgs else None

    return _poll(probe, lambda m: m is not None, timeout_s=timeout_s)


def _role_receive(role_sqs, url):
    msgs = role_sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2).get("Messages", [])
    if not msgs:
        raise _NotYet()
    return msgs[0]


class _NotYet(Exception):
    pass


def _until_allowed(fn, *, timeout_s=120.0, interval_s=3.0):
    """Call ``fn`` until it stops raising AccessDenied (policy propagation), bounded."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied":
                raise
            last = exc.response["Error"]["Code"]
        except _NotYet:
            last = "no message yet"
        if time.monotonic() > deadline:
            raise AssertionError(f"call never became allowed within {timeout_s}s (last={last!r})")
        time.sleep(interval_s)


def _poll(probe, predicate, *, timeout_s, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_role(ctx, account, team=None):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sqsrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust), Tags=[{"Key": "sim2real", "Value": CHECK}]
        + ([{"Key": "sim2real-team", "Value": team}] if team else []),
    )
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    return name, f"arn:aws:iam::{account}:role/{name}"


def _delete_role(iam, name):
    for policy_name in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=name, PolicyName=policy_name)
    iam.delete_role(RoleName=name)


def _assume(ctx, role_arn):
    """Session credentials for ``role_arn``; AssumeRole retries only while the new trust propagates."""
    sts = ctx.client("sts")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            c = sts.assume_role(RoleArn=role_arn, RoleSessionName=SESSION)["Credentials"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    return {
        "aws_access_key_id": c["AccessKeyId"],
        "aws_secret_access_key": c["SecretAccessKey"],
        "aws_session_token": c["SessionToken"],
    }


def _set_policy(sqs, url, doc):
    """SetQueueAttributes(Policy). SQS refuses a principal IAM has not finished propagating with
    InvalidAttributeValue, so that one refusal is retried, bounded."""
    deadline = time.monotonic() + 90.0
    while True:
        try:
            sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(doc)})
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidAttributeValue" or time.monotonic() > deadline:
                raise
            time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
