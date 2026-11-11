"""deploy-cfn-kms-queue-inline-policy-enforces-key-and-queue-grants."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-kms-queue-inline-policy-enforces-key-and-queue-grants"
GROUP = "deploy"
SERVICES = ["sqs"]

SESSION = "sim2real-behav-cfn-kms"


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack KMS key, queue encrypted with it, and QueueInlinePolicy granting a role enforce both:
    the role is refused with KMS.AccessDeniedException (kms:GenerateDataKey) and enqueues nothing
    until granted GenerateDataKey and Decrypt on the key, then sends and receives byte-exact.
    """
    sqs = ctx.client("sqs")
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    role_name, role_arn = _create_role(ctx, account)
    caller = f"arn:aws:sts::{account}:assumed-role/{role_name}/{SESSION}"
    queue_name = ctx.unique_name("sim2real-behav-cfnkms-")

    stack = ctx.unique_name("sim2real-behav-cfnkms-")
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))
    cfn.create_stack(StackName=stack, TemplateBody=json.dumps(_template(account, queue_name)),
                     Parameters=[{"ParameterKey": "GranteeArn", "ParameterValue": role_arn}],
                     Tags=[{"Key": "sim2real", "Value": CHECK}])
    _wait_stack(cfn, stack, "CREATE_COMPLETE")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in cfn.describe_stacks(StackName=stack)["Stacks"][0]["Outputs"]}
    url, key_arn = outputs["QueueUrl"], outputs["KeyArn"]
    queue_arn = f"arn:aws:sqs:{ctx.region}:{account}:{queue_name}"

    attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"])["Attributes"]
    assert attrs.get("KmsMasterKeyId") == key_arn, f"deployed queue KmsMasterKeyId {attrs.get('KmsMasterKeyId')!r}"
    assert attrs.get("SqsManagedSseEnabled") == "false", f"deployed queue SqsManagedSseEnabled {attrs.get('SqsManagedSseEnabled')!r}"
    stored = json.loads(attrs["Policy"])
    assert stored["Statement"][0]["Condition"] == {"ArnEquals": {"aws:PrincipalArn": role_arn}}, f"deployed policy {stored!r}"

    owner_body = "owner-through-stack-key-é中\U0001f600"
    sqs.send_message(QueueUrl=url, MessageBody=owner_body)
    assert _drain(sqs, url) == [owner_body], "the owner could not round-trip through the stack key"

    role_sqs = ctx.client("sqs", creds=_assume(ctx, role_arn))

    def _send():
        try:
            role_sqs.send_message(QueueUrl=url, MessageBody="role-without-key-grant")
        except ClientError as exc:
            return exc.response["Error"]
        return {"Code": "<accepted>", "Message": ""}

    err = _poll(_send, lambda e: e["Code"] != "AccessDenied", timeout_s=120.0, interval_s=3.0)
    assert err["Code"] == "KMS.AccessDeniedException", f"the role's send through the inline policy gave {err!r}"
    expected = (
        f"User: {caller} is not authorized to perform: kms:GenerateDataKey on resource: {key_arn} "
        f"because no identity-based policy allows the kms:GenerateDataKey action "
        f"(Service: AWSKMS; Status Code: 400; Error Code: AccessDeniedException; Request ID: <request-id>; Proxy: null)"
    )
    assert _redact_request_id(err["Message"]) == expected, f"got {err['Message']!r}"
    assert _drain(sqs, url, timeout_s=4.0) == [], "a KMS-refused send must enqueue nothing"

    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-stack-key",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["kms:GenerateDataKey", "kms:Decrypt"], "Resource": key_arn}],
        }),
    )
    body = f"role-with-key-grant-{role_name}"
    deadline = time.monotonic() + 120.0
    while True:
        try:
            role_sqs.send_message(QueueUrl=url, MessageBody=body)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "KMS.AccessDeniedException" or time.monotonic() > deadline:
                raise
        time.sleep(3)
    got = None
    deadline = time.monotonic() + 120.0
    while got is None:
        try:
            msgs = role_sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2).get("Messages", [])
            got = msgs[0] if msgs else None
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "KMS.AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
        if got is None and time.monotonic() > deadline:
            raise AssertionError("the role never received its own message within 120s")
    assert got["Body"] == body, f"the role received {got['Body']!r}, expected {body!r}"
    role_sqs.delete_message(QueueUrl=url, ReceiptHandle=got["ReceiptHandle"])


def _template(account, queue_name):
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"GranteeArn": {"Type": "String"}},
        "Resources": {
            "Key": {
                "Type": "AWS::KMS::Key",
                "DeletionPolicy": "Delete",
                "UpdateReplacePolicy": "Delete",
                "Properties": {
                    "Description": queue_name,
                    "PendingWindowInDays": 7,
                    "KeyPolicy": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Sid": "account-delegates-to-iam",
                            "Effect": "Allow",
                            "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                            "Action": "kms:*",
                            "Resource": "*",
                        }],
                    },
                    "Tags": [{"Key": "sim2real", "Value": CHECK}],
                },
            },
            "Queue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": queue_name, "KmsMasterKeyId": {"Fn::GetAtt": ["Key", "Arn"]}},
            },
            "InlinePolicy": {
                "Type": "AWS::SQS::QueueInlinePolicy",
                "Properties": {
                    "Queue": {"Ref": "Queue"},
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Sid": "grantee",
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": ["sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage"],
                            "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                            "Condition": {"ArnEquals": {"aws:PrincipalArn": {"Ref": "GranteeArn"}}},
                        }],
                    },
                },
            },
        },
        "Outputs": {"QueueUrl": {"Value": {"Ref": "Queue"}}, "KeyArn": {"Value": {"Fn::GetAtt": ["Key", "Arn"]}}},
    }


def _redact_request_id(message):
    """Replace the KMS request id inside ``message`` with a placeholder, asserting it is a UUID."""
    head, sep, tail = message.partition("; Request ID: ")
    assert sep, f"KMS error message carries no request id: {message!r}"
    request_id, sep2, rest = tail.partition(";")
    uuid.UUID(request_id)
    return f"{head}{sep}<request-id>{sep2}{rest}"


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
