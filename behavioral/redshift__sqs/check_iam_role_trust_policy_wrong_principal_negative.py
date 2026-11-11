"""iam-role-trust-policy-wrong-principal-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "iam-role-trust-policy-wrong-principal-negative"
GROUP = "permission-boundary"
SERVICES = ["redshift", "sqs"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """A role whose trust policy names only ec2.amazonaws.com cannot be assumed by the caller's account
    (AccessDenied with its exact message), while a sibling role with the same SQS policy trusting
    the account root is assumable."""
    sts = ctx.client("sts")
    ctx.client("iam")
    identity = sts.get_caller_identity()
    account = identity["Account"]
    caller_arn = identity["Arn"]

    queue = _create_queue(ctx, "trustneg-q")
    sqs_send_policy = json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue["arn"]}]}
    )

    good_role = _create_role_with_trust(
        ctx,
        "trust-good-role",
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"}, "Action": "sts:AssumeRole"}]},
        sqs_send_policy,
    )
    bad_role = _create_role_with_trust(
        ctx,
        "trust-bad-role",
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]},
        sqs_send_policy,
    )

    # Positive control: trust naming our own account root lets us assume it
    # (allow for IAM trust-policy propagation delay with a bounded retry poll).
    creds = _poll_assume_role(ctx, good_role["Arn"], "sim2real-good-session", timeout_s=30.0)
    assert creds is not None and "AccessKeyId" in creds, "positive control failed: correctly-trusted role was not assumable"

    # Negative: trust naming an unrelated AWS service principal blocks us.
    code, msg = _client_error(lambda: sts.assume_role(RoleArn=bad_role["Arn"], RoleSessionName="sim2real-bad-session"))
    assert code == "AccessDenied", f"expected AccessDenied for a role trusting only ec2.amazonaws.com, got {code!r}"
    assert msg == (
        f"User: {caller_arn} is not authorized to perform: sts:AssumeRole on resource: {bad_role['Arn']}"
    ), msg


def _queue_arn(sqs, url: str) -> str:
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]


def _create_queue(ctx, suffix: str) -> dict:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name(f"sim2real-{suffix}-"), tags={"sim2real-check": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"url": url, "arn": _queue_arn(sqs, url)}


def _create_role_with_trust(ctx, suffix: str, trust_policy: dict, inline_policy_doc: str) -> dict:
    iam = ctx.client("iam")
    name = ctx.unique_name(f"sim2real-{suffix}-")
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(RoleName=name, PolicyName="SqsSend", PolicyDocument=inline_policy_doc)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="SqsSend"))
    return {"name": name, "Arn": role["Arn"]}


def _poll_assume_role(ctx, role_arn: str, session_name: str, timeout_s: float = 30.0):
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_creds = None
    while time.monotonic() < deadline:
        try:
            resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
            last_creds = resp["Credentials"]
            return last_creds
        except Exception:
            time.sleep(2)
    return last_creds


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
