"""queue-policy-naming-the-same-queue-name-in-another-region-grants-nothing."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "queue-policy-naming-the-same-queue-name-in-another-region-grants-nothing"
GROUP = "cross-region"
SERVICES = ["sqs"]

SESSION = "sim2real-behav-xr-policy"
_NO_SUCH_QUEUE = "AWS.SimpleQueueService.NonExistentQueue"


def _other_region(region):
    return "us-east-1" if region != "us-east-1" else "us-west-2"


def _delete_quietly(sqs, url):
    try:
        sqs.delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != _NO_SUCH_QUEUE:
            raise


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A home-queue policy statement whose Resource is a same-named queue's ARN in another region is
    stored as written but authorizes sends to neither queue; pointing it at the home ARN admits sends
    home only, and only that message lands on the home queue.
    """
    home = ctx.client("sqs")
    alt_region = _other_region(ctx.region)
    alt = ctx.client("sqs", region=alt_region)
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-xr-pol-")

    home_url = home.create_queue(QueueName=name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_quietly(home, home_url))
    far_url = alt.create_queue(QueueName=name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_quietly(alt, far_url))
    home_arn = home.get_queue_attributes(QueueUrl=home_url, AttributeNames=["QueueArn"])[
        "Attributes"]["QueueArn"]
    far_arn = alt.get_queue_attributes(QueueUrl=far_url, AttributeNames=["QueueArn"])[
        "Attributes"]["QueueArn"]
    assert home_arn != far_arn and home_arn.rsplit(":", 1)[-1] == far_arn.rsplit(":", 1)[-1], (
        "the two queues must share a name and differ only by region"
    )

    role_name, role_arn = _create_role(ctx, account)
    caller = f"arn:aws:sts::{account}:assumed-role/{role_name}/{SESSION}"
    _set_policy(home, home_url, _policy(role_arn, home_arn, send_resource=far_arn))
    creds = _assume(ctx, role_arn)
    role_home = ctx.client("sqs", creds=creds)
    role_far = ctx.client("sqs", region=alt_region, creds=creds)

    seen = _until_allowed(
        lambda: role_home.get_queue_attributes(QueueUrl=home_url, AttributeNames=["QueueArn"]))
    assert seen["Attributes"]["QueueArn"] == home_arn, f"role read {seen['Attributes']!r}"

    stored = json.loads(home.get_queue_attributes(
        QueueUrl=home_url, AttributeNames=["Policy"])["Attributes"]["Policy"])
    send_stmt = next(s for s in stored["Statement"] if s.get("Sid") == "send")
    assert send_stmt["Resource"] == far_arn, (
        f"the home policy should store the other region's ARN as written, got {send_stmt!r}"
    )

    err = _error(lambda: role_home.send_message(QueueUrl=home_url, MessageBody="home-under-far"))
    assert err["Code"] == "AccessDenied", f"send home under a far-region statement gave {err!r}"
    assert err["Message"] == _denied(caller, "sendmessage", home_arn), f"got {err['Message']!r}"
    err = _error(lambda: role_far.send_message(QueueUrl=far_url, MessageBody="far-via-home"))
    assert err["Code"] == "AccessDenied", (
        f"the home queue's policy must not authorize sends to the far queue; got {err!r}"
    )
    assert err["Message"] == _denied(caller, "sendmessage", far_arn), f"got {err['Message']!r}"

    _set_policy(home, home_url, _policy(role_arn, home_arn, send_resource=home_arn))
    body = f"home-under-home-{role_name}"
    _until_allowed(lambda: role_home.send_message(QueueUrl=home_url, MessageBody=body),
                   timeout_s=180.0)
    err = _error(lambda: role_far.send_message(QueueUrl=far_url, MessageBody="far-still"))
    assert err["Code"] == "AccessDenied", f"the far queue must stay closed; got {err!r}"

    on_home = _poll(
        lambda: home.receive_message(QueueUrl=home_url, MaxNumberOfMessages=10,
                                     WaitTimeSeconds=2).get("Messages", []),
        lambda msgs: len(msgs) > 0, timeout_s=30.0)
    assert [m["Body"] for m in on_home] == [body], (
        f"the home queue held {[m['Body'] for m in on_home]!r}, expected [{body!r}]"
    )
    on_far = alt.receive_message(QueueUrl=far_url, MaxNumberOfMessages=10,
                                 WaitTimeSeconds=2).get("Messages", [])
    assert on_far == [], f"the far queue must hold nothing; it held {[m['Body'] for m in on_far]!r}"


def _policy(role_arn, queue_arn, *, send_resource):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "read", "Effect": "Allow", "Principal": {"AWS": role_arn},
             "Action": "sqs:GetQueueAttributes", "Resource": queue_arn},
            {"Sid": "send", "Effect": "Allow", "Principal": {"AWS": role_arn},
             "Action": "sqs:SendMessage", "Resource": send_resource},
        ],
    }


def _denied(caller, action, queue_arn):
    return (
        f"User: {caller} is not authorized to perform: sqs:{action} on resource: {queue_arn} "
        f"because no identity-based policy allows the sqs:{action} action"
    )


def _error(fn):
    """The Error dict ``fn`` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


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
