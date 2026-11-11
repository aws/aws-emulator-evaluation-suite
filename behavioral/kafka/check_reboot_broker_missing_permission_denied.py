"""reboot-broker-missing-permission-denied."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reboot-broker-missing-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["kafka"]

_SESSION_NAME = "sim2real-behav-reboot-broker"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RebootBroker from a role whose policy denies kafka:RebootBroker fails with AccessDeniedException and
    the exact explicit-deny message, while the same bogus ClusterArn from the full-permission caller fails
    with NotFoundException."""
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    kafka = ctx.client("kafka")
    account = sts.get_caller_identity()["Account"]

    # A syntactically valid but non-existent MSK cluster ARN -- avoids provisioning a
    # real cluster since IAM authorization is evaluated before resource lookup.
    bogus_arn = (
        f"arn:aws:kafka:{ctx.region}:{account}:cluster/"
        f"{ctx.unique_name('sim2real-bogus-')}/{uuid.uuid4()}-1"
    )

    role_name = ctx.unique_name("sim2real-kafka-deny-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
            "Action": "sts:AssumeRole",
        }],
    }
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Deny",
            "Action": "kafka:RebootBroker",
            "Resource": "*",
        }],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_json(trust_policy))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="deny-reboot-broker", PolicyDocument=_json(deny_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="deny-reboot-broker"))
    role_arn = f"arn:aws:iam::{account}:role/{role_name}"

    restricted_kafka = _wait_for_assumable_role(ctx, role_arn)

    def _restricted_call():
        restricted_kafka.reboot_broker(ClusterArn=bogus_arn, BrokerIds=["1"])

    restricted = _error_code(_restricted_call)
    expected_denial = (
        "AccessDeniedException",
        f"User: arn:aws:sts::{account}:assumed-role/{role_name}/{_SESSION_NAME} is not authorized "
        f"to perform: kafka:RebootBroker on resource: {bogus_arn} with an explicit deny in an "
        f"identity-based policy",
    )
    assert restricted == expected_denial, f"expected {expected_denial!r}, got {restricted!r}"

    # Positive control: the very same bogus ARN, called with full permissions, is rejected
    # for the resource-not-found reason instead -- proving the negative above was really
    # about the missing IAM permission and not some intrinsic problem with the request.
    def _admin_call():
        kafka.reboot_broker(ClusterArn=bogus_arn, BrokerIds=["1"])

    admin = _error_code(_admin_call)
    expected_miss = ("NotFoundException", "The requested resource doesn\u2019t exist.")
    assert admin == expected_miss, (
        f"expected {expected_miss!r} from the admin caller, got {admin!r}"
    )


def _json(obj) -> str:
    import json
    return json.dumps(obj)


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    SUCCESS raises, because a target ACCEPTING a call real AWS refuses is the strongest signal."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _wait_for_assumable_role(ctx, role_arn: str, timeout_s: float = 60.0):
    """IAM role/policy creation is eventually consistent; poll AssumeRole until it succeeds."""
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(
                RoleArn=role_arn, RoleSessionName=_SESSION_NAME
            )["Credentials"]
            return ctx.client("kafka", creds={
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds["SessionToken"],
            })
        except ClientError as e:
            last_err = e
            time.sleep(2.0)
    raise AssertionError(f"role never became assumable within {timeout_s}s: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
