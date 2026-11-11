"""deploy-iam-managed-policy-via-cloudformation-attaches-and-enforces."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-iam-managed-policy-via-cloudformation-attaches-and-enforces"
GROUP = "deploy"
SERVICES = ["iam"]

_SESSION_NAME = "sim2real-behav-cfnpolicy"


def _budget_s(ctx, cap_s):
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


@tags("axis:happy-path", "cap:c3", "cap:c4", "cap:c7", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CFN AWS::IAM::ManagedPolicy attached via Roles simulates allowed/implicitDeny and enforces:
    an assumed session can GetObject and gets AccessDenied on DeleteObject.
    """
    iam = ctx.client("iam")
    cfn = ctx.client("cloudformation")
    sts = ctx.client("sts")
    s3 = ctx.client("s3")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-behav-role-")
    policy_name = ctx.unique_name("sim2real-behav-policy-")
    stack_name = ctx.unique_name("sim2real-behav-stack-")
    bucket_name = ctx.unique_name("sim2real-behav-bucket-").lower().replace("_", "-")
    object_key = "testobj"
    object_body = b"sim2real-behav-managed-policy-enforcement"

    # us-east-1 is the one region S3 rejects a LocationConstraint for.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))
    s3.put_object(Bucket=bucket_name, Key=object_key, Body=object_body)

    bucket_resource = f"arn:aws:s3:::{bucket_name}/*"
    object_arn = f"arn:aws:s3:::{bucket_name}/{object_key}"

    template = {
        "Resources": {
            "TestRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                },
            },
            "TestManagedPolicy": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                    "ManagedPolicyName": policy_name,
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": bucket_resource}
                        ],
                    },
                    "Roles": [{"Ref": "TestRole"}],
                },
            },
        },
        "Outputs": {
            "RoleArn": {"Value": {"Fn::GetAtt": ["TestRole", "Arn"]}},
            "PolicyArn": {"Value": {"Ref": "TestManagedPolicy"}},
        },
    }
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name))
    stack = _wait_stack_status(ctx, stack_name, {"CREATE_COMPLETE"})
    outputs = _stack_outputs(stack)
    role_arn, policy_arn = outputs["RoleArn"], outputs["PolicyArn"]

    policy = iam.get_policy(PolicyArn=policy_arn)["Policy"]
    assert policy["PolicyName"] == policy_name
    assert policy["Arn"] == policy_arn

    # The simulator's EvalDecision is advisory; the signed calls below must agree with it.
    allow_result = iam.simulate_principal_policy(
        PolicySourceArn=role_arn,
        ActionNames=["s3:GetObject"],
        ResourceArns=[object_arn],
    )["EvaluationResults"][0]
    assert allow_result["EvalDecision"] == "allowed", (
        f"the CFN-attached policy grants s3:GetObject on {object_arn!r}, so the simulator must say "
        f"'allowed'; got {allow_result['EvalDecision']!r}"
    )

    deny_result = iam.simulate_principal_policy(
        PolicySourceArn=role_arn,
        ActionNames=["s3:DeleteObject"],
        ResourceArns=[object_arn],
    )["EvaluationResults"][0]
    assert deny_result["EvalDecision"] == "implicitDeny", (
        f"s3:DeleteObject appears in no statement, so the simulator must say 'implicitDeny' -- not "
        f"'explicitDeny' and not 'allowed'; got {deny_result['EvalDecision']!r}"
    )

    # IAM reports neither the trust policy nor the permission policy as effective, so both the
    # assume and the granted call are bounded polls.
    creds = _assume(sts, role_arn, _SESSION_NAME, timeout_s=_budget_s(ctx, 90.0))
    as_role = _client_for_session(ctx, creds, "s3")

    got = _poll(
        lambda: _try_get_object(as_role, bucket_name, object_key),
        lambda r: r[0] == "OK",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the CFN-attached managed policy's grant becomes effective for the assumed session",
    )
    assert got[0] == "OK", (
        "the simulator said s3:GetObject is allowed for this role, so a real signed GetObject by a "
        f"session assumed from it must succeed; it returned {got[0]!r}"
    )
    assert got[1] == object_body, (
        f"the assumed session's GetObject must return the object this check wrote: expected "
        f"{object_body!r}, got {got[1]!r}"
    )

    denied, denied_message = _error(lambda: as_role.delete_object(Bucket=bucket_name, Key=object_key))
    assert denied == "AccessDenied", (
        "the simulator said s3:DeleteObject is implicitDeny for this role, so a real signed "
        f"DeleteObject by a session assumed from it must be refused with exactly AccessDenied; got "
        f"{denied!r}"
    )
    expected_message = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{_SESSION_NAME} is not authorized "
        f'to perform: s3:DeleteObject on resource: "{object_arn}" because no identity-based policy '
        "allows the s3:DeleteObject action"
    )
    assert denied_message == expected_message, (
        f"expected AccessDenied message {expected_message!r}, got {denied_message!r}"
    )

    # One equality over both views, so a disagreement names the action.
    simulated = {
        "s3:GetObject": allow_result["EvalDecision"] == "allowed",
        "s3:DeleteObject": deny_result["EvalDecision"] == "allowed",
    }
    enforced = {"s3:GetObject": got[0] == "OK", "s3:DeleteObject": denied != "AccessDenied"}
    assert simulated == enforced, (
        "SimulatePrincipalPolicy and the enforcement path disagree for this CFN-attached role: "
        f"simulator said {simulated!r}, the real signed calls behaved as {enforced!r}"
    )


def _assume(sts, role_arn, session_name, *, timeout_s=90.0, interval_s=3.0):
    """AssumeRole with a bounded retry: a new role 403s until its trust policy propagates."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
        except ClientError as exc:
            last = exc.response.get("Error", {}).get("Code")
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"could not assume {role_arn} within {timeout_s}s; last error {last!r}"
                ) from exc
            time.sleep(interval_s)


def _client_for_session(ctx, creds, service):
    """A client signing AS the minted principal, against the same target as ctx.client()."""
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not reached within {timeout_s}s; last observation {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


def _try_get_object(client, bucket, key):
    """(code_or_OK, body_or_None) for a real signed GetObject -- one probe, two observations."""
    try:
        return "OK", client.get_object(Bucket=bucket, Key=key)["Body"].read()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), None


def _error(fn):
    """(code, message) of the ClientError fn raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _empty_and_delete_bucket(s3, bucket_name):
    objects = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
    for obj in objects:
        s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket_name)


def _wait_stack_status(ctx, stack_name, ok_statuses, timeout_s=600.0, interval_s=5.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        status = stacks[0]["StackStatus"]
        if status in ok_statuses:
            return stacks[0]
        if status.endswith("FAILED") or status == "ROLLBACK_COMPLETE":
            raise AssertionError(f"stack {stack_name} entered unexpected status {status}")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach {ok_statuses} within {timeout_s}s")


def _wait_stack_deleted(ctx, stack_name, timeout_s=600.0, interval_s=5.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            if "does not exist" in str(exc):
                return
            raise
        status = stacks[0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} entered DELETE_FAILED")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} was not deleted within {timeout_s}s")


def _delete_stack_and_wait(ctx, stack_name):
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    _wait_stack_deleted(ctx, stack_name)


def _stack_outputs(stack):
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
