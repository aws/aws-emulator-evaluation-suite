"""create-vpc-connection-forbidden-without-permission."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-vpc-connection-forbidden-without-permission"
GROUP = "overly-permissive"
SERVICES = ["kafka"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A role with kafka:* but an inline Deny on kafka:CreateVpcConnection gets AccessDeniedException,
    while ListVpcConnections still succeeds; once the Deny is removed the same call is no longer
    rejected by IAM.
    """
    kafka = ctx.client("kafka")
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-kafka-deny-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_ignore(ctx, role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonMSKFullAccess")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="deny-create-vpc-connection",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Deny", "Action": "kafka:CreateVpcConnection", "Resource": "*"}],
            }
        ),
    )

    # A syntactically valid but non-existent target cluster is fine: IAM authorization
    # is evaluated before resource-existence checks, so the ONLY thing broken here is
    # the missing permission. The same reasoning applies to the VPC/subnet/security-group
    # identifiers below: they need only be syntactically plausible, so the check has no
    # dependency on an ambient default VPC that a freshly provisioned account may lack.
    bogus_cluster_arn = (
        f"arn:aws:kafka:{ctx.region}:{account_id}:cluster/sim2real-nonexistent/"
        "00000000-0000-0000-0000-000000000000-1"
    )
    vpc_id = "vpc-00000000000000000"
    subnet_id = "subnet-00000000000000000"
    sg_id = "sg-00000000000000000"

    denied_client = _wait_for_assumable_role(ctx, role_arn, "kafka")

    def _create():
        return denied_client.create_vpc_connection(
            TargetClusterArn=bogus_cluster_arn,
            Authentication="IAM",
            VpcId=vpc_id,
            ClientSubnets=[subnet_id],
            SecurityGroups=[sg_id],
        )

    code, _, message = _error_code_and_arn_with_retry(_create, retryable=set())
    # IAM-level explicit Deny is enforced by the AWS request-authorization layer
    # before the request reaches the Kafka control plane, so it surfaces as the
    # generic IAM AccessDeniedException rather than the service-modeled
    # ForbiddenException (which the Kafka API reserves for its own internal
    # authorization checks, e.g. resource policies).
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    expected_message = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{_SESSION_NAME} is not "
        f"authorized to perform: kafka:CreateVpcConnection on resource: {bogus_cluster_arn} "
        "with an explicit deny in an identity-based policy"
    )
    assert message == expected_message, f"unexpected message: {message!r}"

    # Positive control: the same identity CAN still call an action that isn't denied.
    denied_client.list_vpc_connections()

    # Restore: remove the inline Deny and prove the IDENTICAL call is no longer blocked
    # by IAM. The fabricated cluster/VPC/subnet/security-group values still make it fail
    # -- but now with a service-level error rather than AccessDeniedException, proving
    # the earlier rejection was specific to the one missing permission and not a fluke.
    iam.delete_role_policy(RoleName=role_name, PolicyName="deny-create-vpc-connection")
    restored_code, restored_arn, _ = _error_code_and_arn_with_retry(_create, retryable={"AccessDeniedException"}, timeout_s=240)
    if restored_arn:
        ctx.on_cleanup(lambda: _delete_vpc_connection_ignore(ctx, restored_arn))
    assert restored_code != "AccessDeniedException", (
        f"expected the restored identity's call to no longer be denied by IAM, got {restored_code!r}"
    )


def _delete_role_ignore(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for policy_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        for attached in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=attached["PolicyArn"])
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


_SESSION_NAME = "sim2real-kafka-negative"


def _wait_for_assumable_role(ctx, role_arn, service, *, timeout_s=60, interval_s=5):
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)["Credentials"]
            return ctx.client(
                service,
                creds={
                    "aws_access_key_id": creds["AccessKeyId"],
                    "aws_secret_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"],
                },
            )
        except ClientError as err:
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"could not assume role {role_arn} within {timeout_s}s: {last_err}")


def _error_code_and_arn_with_retry(fn, *, retryable=frozenset(), timeout_s=60, interval_s=5):
    deadline = time.monotonic() + timeout_s
    code = message = None
    while time.monotonic() < deadline:
        try:
            resp = fn()
            return None, resp.get("VpcConnectionArn"), None
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message")
            if code not in retryable:
                return code, None, message
            time.sleep(interval_s)
    return code, None, message


def _delete_vpc_connection_ignore(ctx, arn: str) -> None:
    kafka = ctx.client("kafka")
    try:
        kafka.delete_vpc_connection(Arn=arn)
    except ClientError as err:
        if err.response["Error"]["Code"] == "NotFoundException":
            return
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
