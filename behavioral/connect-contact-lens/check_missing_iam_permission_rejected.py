"""missing-iam-permission-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "missing-iam-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["connect-contact-lens"]

NOT_FOUND = "Real-time contact analysis not found."
SESSION_NAME = "sim2real-behav-session"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListRealtimeContactAnalysisSegments by a role denied that action fails with HTTP 403
    AccessDeniedException and its exact message, while the same request from the check's own identity
    fails with ResourceNotFoundException."""
    connect = ctx.client("connect")
    _create_active_instance(ctx, connect)
    account_id, role_name, role_arn = _create_deny_role(ctx)
    restricted = _assume_role_client(ctx, "connect-contact-lens", role_arn)

    fake_instance = str(uuid.uuid4())
    fake_contact = str(uuid.uuid4())

    try:
        resp = restricted.list_realtime_contact_analysis_segments(
            InstanceId=fake_instance, ContactId=fake_contact
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "AccessDeniedException", (
            f"expected AccessDeniedException for a denied caller, got {code!r}"
        )
        message = err.response["Error"]["Message"]
        expected = (
            f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{SESSION_NAME} "
            "is not authorized to perform: connect:ListRealtimeContactAnalysisSegments "
            f"on resource: arn:aws:connect:{ctx.region}:{account_id}:instance/"
            f"{fake_instance}/contact/{fake_contact} with an explicit deny in an "
            "identity-based policy"
        )
        assert message == expected, f"unexpected AccessDeniedException message {message!r}"
        status = err.response["ResponseMetadata"]["HTTPStatusCode"]
        assert status == 403, f"expected HTTP 403 for AccessDeniedException, got {status!r}"
        assert "Segments" not in err.response, (
            f"the error body must not leak partial data-plane content: {err.response!r}"
        )
    else:
        raise AssertionError(
            f"expected AccessDeniedException, got a 200 response instead: {resp}"
        )

    # positive control: the check's own (unrestricted) credentials, same request
    privileged = ctx.client("connect-contact-lens")
    try:
        privileged.list_realtime_contact_analysis_segments(
            InstanceId=fake_instance, ContactId=fake_contact
        )
        raise AssertionError("expected an error, privileged call returned 200")
    except ClientError as err:
        control = err.response["Error"]
    assert control["Code"] == "ResourceNotFoundException", (
        f"privileged control produced {control['Code']!r}, expected "
        "ResourceNotFoundException (i.e. it must clear authorization)"
    )
    assert control["Message"] == NOT_FOUND, (
        f"unexpected ResourceNotFoundException message {control['Message']!r}"
    )


def _create_active_instance(ctx, connect, timeout_s=270.0, interval_s=5.0):
    """A new Connect instance, waited to ACTIVE."""
    instance_id = connect.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=ctx.unique_name("sim2real-behav-"),
        InboundCallsEnabled=True,
        OutboundCallsEnabled=True,
        Tags={"sim2real": CHECK},
    )["Id"]
    ctx.on_cleanup(lambda: _delete_instance(connect, instance_id))
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = connect.describe_instance(InstanceId=instance_id)["Instance"]
        if last["InstanceStatus"] == "ACTIVE":
            return instance_id
        time.sleep(interval_s)
    raise AssertionError(f"instance {instance_id} never reached ACTIVE, last={last}")


def _delete_instance(connect, instance_id):
    try:
        connect.delete_instance(InstanceId=instance_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_deny_role(ctx) -> tuple[str, str, str]:
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-deny-")

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "connect:ListRealtimeContactAnalysisSegments",
                "Resource": "*",
            }
        ],
    }
    policy_name = f"{role_name}-deny"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(deny_policy),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )
    return account_id, role_name, role_arn


def _assume_role_client(ctx, service, role_arn, timeout_s=45.0, interval_s=3.0):
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_err = None
    creds = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName=SESSION_NAME,
            )["Credentials"]
            break
        except ClientError as err:
            last_err = err
            time.sleep(interval_s)
    if creds is None:
        raise AssertionError(f"could not assume role {role_arn}: {last_err}")

    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
