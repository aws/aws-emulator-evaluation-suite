"""sar-deploy-denied-for-role-scoped-to-another-application."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sar-deploy-denied-for-role-scoped-to-another-application"
GROUP = "deploy-authorization"
SERVICES = ["serverlessrepo"]

_PROPAGATION_WAIT_S = 120
_STACK_WAIT_S = 600

_SAM_TEMPLATE = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Transform": "AWS::Serverless-2016-10-31",
    "Parameters": {"QueueNameParam": {"Type": "String"}},
    "Resources": {
        "Q": {
            "Type": "AWS::SQS::Queue",
            "Properties": {"QueueName": {"Ref": "QueueNameParam"}},
        }
    },
    "Outputs": {"QueueUrl": {"Value": {"Ref": "Q"}}},
}


@tags(
    "axis:rejection",
    "cap:c7",
    "concern:deploy",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A role whose policy names one SAR application can create a change set for and read that
    application, but is refused for a second application in the same account with 403
    AccessDeniedException naming the action and its ARN, and no stack is created for it."""
    sar = ctx.client("serverlessrepo")
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    allowed_id = _publish(ctx, sar, "sim2real-behav-sarok-")
    denied_id = _publish(ctx, sar, "sim2real-behav-sarno-")

    account = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-sarrole-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = ctx.unique_name("sim2real-behav-sarpol-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "serverlessrepo:CreateCloudFormationChangeSet",
                            "serverlessrepo:GetApplication",
                        ],
                        # Scoped to ONE application ARN; the other one is not named anywhere.
                        "Resource": allowed_id,
                    },
                    # CloudFormation and the template read are deliberately wide open: SAR calls
                    # CloudFormation on the caller's behalf, CloudFormation then fetches the
                    # rendered template out of SAR's own change-set bucket as the caller, and
                    # EITHER of those failing is reported as a serverlessrepo BadRequestException
                    # ("S3 error: Access Denied" wrapped in a CloudFormation ValidationError) that
                    # would be indistinguishable from the denial this check is about.
                    {"Effect": "Allow", "Action": "cloudformation:*", "Resource": "*"},
                    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    scoped = ctx.client("serverlessrepo", creds=_assume(ctx, sts, role_arn))

    # ---- positive control: the application the role's policy names
    allowed_stack = ctx.unique_name("sim2real-behav-sarokstk-")
    cut = _create_change_set_when_propagated(ctx, scoped, allowed_id, allowed_stack)
    ctx.on_cleanup(lambda: _delete_stack(cfn, cut["StackId"]))
    assert cut["ApplicationId"] == allowed_id, (
        f"control change set names application {cut['ApplicationId']!r}"
    )

    # ---- the same identity, the same call, the other application
    denied_stack = ctx.unique_name("sim2real-behav-sarnostk-")
    try:
        refused = scoped.create_cloud_formation_change_set(
            ApplicationId=denied_id,
            StackName=denied_stack,
            SemanticVersion="1.0.0",
            ParameterOverrides=[
                {"Name": "QueueNameParam", "Value": ctx.unique_name("sim2real-behav-sarq-")}
            ],
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        status = exc.response["ResponseMetadata"]["HTTPStatusCode"]
        message = exc.response["Error"]["Message"]
    else:
        ctx.on_cleanup(lambda: _delete_stack(cfn, refused["StackId"]))
        raise AssertionError(
            f"a role scoped to {allowed_id!r} cut a change set for {denied_id!r}: "
            f"{refused['ChangeSetId']!r}"
        )

    assert code == "AccessDeniedException", (
        f"denial code is {code!r}, expected AccessDeniedException"
    )
    assert status == 403, f"denial status is {status!r}, expected 403"
    caller = f"arn:aws:sts::{account}:assumed-role/{role_name}/sim2real-behav"
    expected = (
        f"User: {caller} is not authorized to perform: "
        f"serverlessrepo:CreateCloudFormationChangeSet on resource: {denied_id} because no "
        f"identity-based policy allows the serverlessrepo:CreateCloudFormationChangeSet action"
    )
    assert message == expected, f"denial message is {message!r}, expected {expected!r}"

    # A read of the same unnamed application is refused too — the scope is the application, not
    # the one operation.
    read_code, read_message = _error(lambda: scoped.get_application(ApplicationId=denied_id))
    assert read_code == "AccessDeniedException", (
        f"GetApplication on the unnamed application returned {read_code!r}"
    )
    expected = (
        f"User: {caller} is not authorized to perform: serverlessrepo:GetApplication on "
        f"resource: {denied_id} because no identity-based policy allows the "
        f"serverlessrepo:GetApplication action"
    )
    assert read_message == expected, (
        f"GetApplication denial message is {read_message!r}, expected {expected!r}"
    )

    # ...and the allowed application is still readable under the same identity.
    assert scoped.get_application(ApplicationId=allowed_id)["ApplicationId"] == allowed_id, (
        "the role lost access to the application its policy names"
    )

    # The denial left nothing behind.
    assert not _stack_exists(cfn, f"serverlessrepo-{denied_stack}"), (
        f"a stack serverlessrepo-{denied_stack!r} exists after the denial"
    )


def _publish(ctx, sar, prefix: str) -> str:
    created = sar.create_application(
        Name=ctx.unique_name(prefix),
        Author="sim2real-behav",
        Description="sim2real SAR deploy authorization check",
        TemplateBody=json.dumps(_SAM_TEMPLATE),
        SemanticVersion="1.0.0",
    )
    app_id = created["ApplicationId"]
    ctx.on_cleanup(lambda: sar.delete_application(ApplicationId=app_id))
    return app_id


def _assume(ctx, sts, role_arn: str) -> dict:
    deadline = time.time() + _PROPAGATION_WAIT_S
    last = None
    while time.time() < deadline:
        try:
            got = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-behav")
        except ClientError as exc:
            last = exc
            time.sleep(3)
            continue
        return {
            "aws_access_key_id": got["Credentials"]["AccessKeyId"],
            "aws_secret_access_key": got["Credentials"]["SecretAccessKey"],
            "aws_session_token": got["Credentials"]["SessionToken"],
        }
    raise AssertionError(f"could not assume {role_arn!r} within {_PROPAGATION_WAIT_S}s: {last!r}")


def _create_change_set_when_propagated(ctx, scoped, app_id: str, stack_name: str) -> dict:
    """The positive control, retried only while IAM is still propagating the fresh role policy."""
    deadline = time.time() + _PROPAGATION_WAIT_S
    last = None
    while time.time() < deadline:
        try:
            return scoped.create_cloud_formation_change_set(
                ApplicationId=app_id,
                StackName=stack_name,
                SemanticVersion="1.0.0",
                ParameterOverrides=[
                    {"Name": "QueueNameParam", "Value": ctx.unique_name("sim2real-behav-sarq-")}
                ],
            )
        except ClientError as exc:
            last = exc
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            time.sleep(5)
    raise AssertionError(
        f"the role's own application {app_id!r} was still denied after "
        f"{_PROPAGATION_WAIT_S}s: {last!r}"
    )


def _error(fn) -> tuple[str, str]:
    """The (Code, Message) of the ClientError fn() raises; a success fails the check."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError("the call succeeded; real AWS refuses it")


def _stack_exists(cfn, stack_name: str) -> bool:
    try:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ValidationError":
            return False
        raise
    return bool(stacks) and stacks[0]["StackStatus"] != "DELETE_COMPLETE"


def _delete_stack(cfn, stack_id: str) -> None:
    cfn.delete_stack(StackName=stack_id)
    deadline = time.time() + _STACK_WAIT_S
    while time.time() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_id)["Stacks"]
        if stacks[0]["StackStatus"] == "DELETE_COMPLETE":
            return
        if stacks[0]["StackStatus"] == "DELETE_FAILED":
            raise AssertionError(
                f"stack {stack_id!r} failed to delete: {stacks[0].get('StackStatusReason')!r}"
            )
        time.sleep(5)
    raise AssertionError(f"stack {stack_id!r} did not finish deleting in {_STACK_WAIT_S}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
