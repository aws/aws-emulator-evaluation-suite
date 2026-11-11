"""register-outside-the-allowed-scalable-dimension-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-outside-the-allowed-scalable-dimension-denied"
GROUP = "overly-permissive"
SERVICES = ["application-autoscaling"]

_NS = "dynamodb"
_READ = "dynamodb:table:ReadCapacityUnits"
_WRITE = "dynamodb:table:WriteCapacityUnits"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A principal allowed RegisterScalableTarget only for scalable-dimension ReadCapacityUnits
    registers the read dimension but is denied the write one (AccessDeniedException, no target),
    and needs no DynamoDB permission to register.
    """
    aas = ctx.client("application-autoscaling")
    partition = ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]
    table = _table(ctx)
    resource_id = f"table/{table}"
    for dim in (_READ, _WRITE):
        ctx.on_cleanup(lambda dim=dim: _ignore_missing(
            lambda: aas.deregister_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                                   ScalableDimension=dim),
            "ObjectNotFoundException"))
    role_name, scoped = _principal(ctx, [
        {"Effect": "Allow", "Action": "application-autoscaling:Describe*", "Resource": "*"},
        {"Effect": "Allow", "Action": "application-autoscaling:RegisterScalableTarget",
         "Resource": "*",
         "Condition": {"StringEquals": {"application-autoscaling:scalable-dimension": _READ}}},
    ])

    # Positive control first: it is also the barrier proving the policy has propagated.
    _until_permitted(lambda: scoped.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_READ,
        MinCapacity=1, MaxCapacity=5), "registering the allowed read dimension")
    assert _bounds(aas, resource_id, _READ) == (1, 5), (
        f"the allowed read target has bounds {_bounds(aas, resource_id, _READ)!r}"
    )

    code, message = _error(lambda: scoped.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_WRITE,
        MinCapacity=1, MaxCapacity=5))
    assert code == "AccessDeniedException", f"the write dimension was refused with {code!r}"
    expected = _denied(partition, ctx.account, role_name, "RegisterScalableTarget",
                       f"arn:{partition}:application-autoscaling:{ctx.region}:{ctx.account}:"
                       f"scalable-target/*")
    assert message == expected, f"denial message {message!r}, expected {expected!r}"
    assert _bounds(aas, resource_id, _WRITE) is None, (
        "the denied write dimension is registered anyway"
    )
    assert _bounds(aas, resource_id, _READ) == (1, 5), "the denial disturbed the read target"


def _bounds(aas, resource_id, dim):
    found = []
    for page in aas.get_paginator("describe_scalable_targets").paginate(
            ServiceNamespace=_NS, ResourceIds=[resource_id], ScalableDimension=dim):
        found.extend((t["MinCapacity"], t["MaxCapacity"]) for t in page["ScalableTargets"])
    assert len(found) <= 1, f"{len(found)} targets share one resource id and dimension"
    return found[0] if found else None


_SESSION = "sim2real-aas-session"
_PROPAGATION_S = 90.0


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _ignore_missing(fn, *codes):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in codes:
            raise


def _table(ctx):
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-aas-")
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _ignore_missing(lambda: ddb.delete_table(TableName=name),
                                           "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


def _principal(ctx, statements):
    """A role this check creates, carrying only ``statements``, assumed into a client.

    Returns (role name, application-autoscaling client signed as the role).
    """
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    partition = sts.get_caller_identity()["Arn"].split(":")[1]
    role_name = ctx.unique_name("sim2real-aas-principal-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"AWS": f"arn:{partition}:iam::{ctx.account}:root"},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _drop():
        _ignore_missing(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="scoped"),
                        "NoSuchEntity")
        _ignore_missing(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity")

    ctx.on_cleanup(_drop)
    iam.put_role_policy(RoleName=role_name, PolicyName="scoped",
                        PolicyDocument=json.dumps({"Version": "2012-10-17",
                                                   "Statement": statements}))
    deadline = time.monotonic() + _PROPAGATION_S
    while True:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION)["Credentials"]
            break
        except ClientError as exc:
            # IAM propagation: a fresh role is not assumable at once.
            if exc.response["Error"]["Code"] != "AccessDenied" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    client = ctx.client("application-autoscaling", creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })
    return role_name, client


def _until_permitted(fn, what):
    """First use of a fresh role's permission: retry AccessDenied while IAM propagates."""
    deadline = time.monotonic() + _PROPAGATION_S
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"{what} was still denied after {_PROPAGATION_S}s of IAM propagation: "
                    f"{exc.response['Error'].get('Message')!r}") from exc
            time.sleep(3)


def _denied(partition, account, role_name, action, resource):
    return (f"User: arn:{partition}:sts::{account}:assumed-role/{role_name}/{_SESSION} is not "
            f"authorized to perform: application-autoscaling:{action} on resource: {resource} "
            f"because no identity-based policy allows the application-autoscaling:{action} action")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
