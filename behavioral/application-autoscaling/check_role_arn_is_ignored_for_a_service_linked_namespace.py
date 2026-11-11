"""role-arn-is-ignored-for-a-service-linked-namespace."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "role-arn-is-ignored-for-a-service-linked-namespace"
GROUP = "scalable-targets"
SERVICES = ["application-autoscaling"]

_NS = "dynamodb"
_READ = "dynamodb:table:ReadCapacityUnits"
_WRITE = "dynamodb:table:WriteCapacityUnits"
_FLOOR = 2
_SLR_SUFFIX = ("role/aws-service-role/dynamodb.application-autoscaling.amazonaws.com/"
               "AWSServiceRoleForApplicationAutoScaling_DynamoDBTable")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """For dynamodb, RegisterScalableTarget ignores the supplied RoleARN (a real role or an absent
    one): both targets report the DynamoDB service-linked role, which then applies the read floor.
    """
    aas = ctx.client("application-autoscaling")
    iam = ctx.client("iam")
    ddb = ctx.client("dynamodb")
    partition = ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]
    table = _table(ctx)
    resource_id = f"table/{table}"
    slr = f"arn:{partition}:iam::{ctx.account}:{_SLR_SUFFIX}"

    role_name = ctx.unique_name("sim2real-aas-custom-")
    custom_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": "application-autoscaling.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: iam.delete_role(RoleName=role_name),
                                           "NoSuchEntity"))
    absent_arn = f"arn:{partition}:iam::{ctx.account}:role/{ctx.unique_name('sim2real-aas-absent-')}"

    for dim, role_arn, floor in ((_READ, custom_arn, _FLOOR), (_WRITE, absent_arn, 1)):
        aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                     ScalableDimension=dim, MinCapacity=floor, MaxCapacity=5,
                                     RoleARN=role_arn)
        ctx.on_cleanup(lambda dim=dim: _ignore_missing(
            lambda: aas.deregister_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                                   ScalableDimension=dim),
            "ObjectNotFoundException"))

    for dim, supplied in ((_READ, "a customer role the check created"),
                          (_WRITE, "a role that does not exist")):
        target = _target(aas, resource_id, dim)
        assert target is not None, f"the {dim} target registered with {supplied} is missing"
        assert target["RoleARN"] == slr, (
            f"the {dim} target registered with {supplied} reports RoleARN ending "
            f"{target['RoleARN'].split('/')[-1]!r}; a dynamodb target always uses the "
            f"DynamoDB service-linked role"
        )
    assert iam.get_role(RoleName=role_name)["Role"]["Arn"] == custom_arn, (
        "the customer role changed identity"
    )

    rcu = _poll_until(
        lambda: ddb.describe_table(TableName=table)["Table"]["ProvisionedThroughput"][
            "ReadCapacityUnits"],
        lambda v: v == _FLOOR, timeout_s=180,
        description=f"the service-linked role raising the table's read capacity to {_FLOOR}")
    assert rcu == _FLOOR, rcu


def _target(aas, resource_id, dim):
    found = []
    for page in aas.get_paginator("describe_scalable_targets").paginate(
            ServiceNamespace=_NS, ResourceIds=[resource_id], ScalableDimension=dim):
        found.extend(page["ScalableTargets"])
    assert len(found) <= 1, f"{len(found)} targets share one resource id and dimension"
    return found[0] if found else None


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
