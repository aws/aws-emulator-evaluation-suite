"""activation-with-inline-policy-role-describe-by-id-echoes-fields."""

from __future__ import annotations

import datetime
import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "activation-with-inline-policy-role-describe-by-id-echoes-fields"
GROUP = "state-machine"
SERVICES = ["iam", "ssm"]

_TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ssm.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)
_INLINE = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "ssm:UpdateInstanceInformation", "Resource": "*"}
        ],
    }
)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateActivation for a role with only an inline policy echoes every field by id.

    The ActivationId is a UUID; DescribeActivations filtered by it echoes IamRole, Description,
    DefaultInstanceName, RegistrationLimit, Tags and Expired false, and lists nothing once deleted.
    """
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")

    role_name = ctx.unique_name("sim2real-behav-actrole-")[:64]
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    def delete_role():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="managed-instance")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(delete_role)
    iam.put_role_policy(RoleName=role_name, PolicyName="managed-instance", PolicyDocument=_INLINE)

    description = ctx.unique_name("sim2real-behav-activation-")
    instance_name = ctx.unique_name("sim2real-behav-node-")
    tags_sent = [{"Key": "owner", "Value": "alpha"}]
    propagation_message = (
        "Nonexistent role or missing ssm service principal in trust policy: "
        f"arn:aws:iam::{ctx.account}:role/{role_name}"
    )
    deadline = time.monotonic() + min(60.0, ctx.time_left())
    while True:
        try:
            created = ssm.create_activation(
                IamRole=role_name,
                Description=description,
                DefaultInstanceName=instance_name,
                RegistrationLimit=2,
                Tags=tags_sent,
            )
            break
        except ClientError as exc:
            error = exc.response["Error"]
            propagating = (error["Code"], error.get("Message")) == (
                "ValidationException",
                propagation_message,
            )
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(3)
    activation_id = created["ActivationId"]

    def delete_activation():
        try:
            ssm.delete_activation(ActivationId=activation_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidActivation":
                raise

    ctx.on_cleanup(delete_activation)
    assert re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", activation_id
    ), f"ActivationId {activation_id!r} is not a UUID"
    assert re.fullmatch(r"[A-Za-z0-9+/]{20}", created["ActivationCode"]), (
        f"ActivationCode {created['ActivationCode']!r} has an unexpected form"
    )

    def by_id():
        return ssm.describe_activations(
            Filters=[{"FilterKey": "ActivationIds", "FilterValues": [activation_id]}]
        )["ActivationList"]

    listed = by_id()
    assert len(listed) == 1, f"DescribeActivations by ActivationIds returned {listed!r}"
    item = listed[0]
    created_date, expiration = item.pop("CreatedDate"), item.pop("ExpirationDate")
    assert isinstance(created_date, datetime.datetime), f"CreatedDate is {created_date!r}"
    assert expiration - created_date == datetime.timedelta(hours=24), (
        f"ExpirationDate {expiration!r} is not 24 hours after CreatedDate {created_date!r}"
    )
    expected = {
        "ActivationId": activation_id,
        "Description": description,
        "DefaultInstanceName": instance_name,
        "IamRole": role_name,
        "RegistrationLimit": 2,
        "RegistrationsCount": 0,
        "Expired": False,
        "Tags": tags_sent,
    }
    assert item == expected, f"DescribeActivations echoed {item!r}, expected {expected!r}"

    ssm.delete_activation(ActivationId=activation_id)
    assert by_id() == [], f"a deleted activation still lists: {by_id()!r}"

    try:
        redelete = ssm.delete_activation(ActivationId=activation_id)
    except ClientError as exc:
        dup_error = exc.response["Error"]
    else:
        raise AssertionError(
            f"deleting the already-deleted activation unexpectedly succeeded: {redelete!r}"
        )
    assert (dup_error["Code"], dup_error["Message"]) == ("InvalidActivation", ""), (
        f"deleting a dead activation gave {dup_error!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
