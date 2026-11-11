"""xsvc-dynamodb-2-leading-keys-principal-tag-variable-cross-tenant-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-dynamodb-2-leading-keys-principal-tag-variable-cross-tenant-denied"
GROUP = "overly_permissive"
SERVICES = ["dynamodb", "iam", "sts"]

ERR_ACCESS_DENIED = "AccessDeniedException"
# With no session policy, the refusal is attributed to the
# identity policy whose LeadingKeys condition did not match.
IDENTITY_ATTRIBUTION = "no identity-based policy allows"

TENANT_1 = "tenant-one"
TENANT_2 = "tenant-two"

# ===== helpers =====

_PREFIX = "sim2real-xsvc-"


def _denied(fn):
    """Call fn(); return (code, message) of the ClientError it raises.

    A call that SUCCEEDS is the strongest signal this check exists for (an over-permissive
    target), so it raises rather than returning a falsy sentinel that reads like a code mismatch.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    result = {k: v for k, v in (result or {}).items() if k != "ResponseMetadata"}
    raise AssertionError(f"call was expected to be DENIED but succeeded: {result!r}")


def _retry_denied(fn, *, timeout_s=90.0, interval_s=3.0, description="call"):
    """Retry fn() while it raises AccessDenied* -- IAM role/policy propagation exposes no
    condition to poll, so the bounded retry at first use IS the wait."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if not code.startswith("AccessDenied") or time.monotonic() >= deadline:
                raise AssertionError(
                    f"{description} still failing with {code!r} after {timeout_s}s: "
                    f"{exc.response.get('Error', {}).get('Message')!r}"
                ) from exc
        time.sleep(interval_s)


def _delete_role(iam, role_name):
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=role_name)


def _delete_table(ddb, table):
    deadline = time.monotonic() + 180
    while True:
        try:
            ddb.delete_table(TableName=table)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(5)


def _tagged_client(ctx, role_arn, tenant):
    """A DynamoDB client for a fresh session of ``role_arn``, and the session's principal ARN."""
    sts = ctx.client("sts")
    kw = {"Tags": [{"Key": "tenant", "Value": tenant}]} if tenant else {}
    assumed = _retry_denied(
        lambda: sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=ctx.unique_name("sim2real-pt-")[:64],
            DurationSeconds=3600,
            **kw,
        ),
        description="sts:AssumeRole (+TagSession) on the freshly created role",
    )
    creds = assumed["Credentials"]
    client = ctx.client(
        "dynamodb",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    return client, assumed["AssumedRoleUser"]["Arn"]


def _key(pk, sk):
    return {"pk": {"S": pk}, "sk": {"S": sk}}


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """ONE role whose policy restricts dynamodb:LeadingKeys to "${aws:PrincipalTag/tenant}" lets a
    session tagged with a tenant read and write only that tenant's partition (AccessDeniedException
    on the other's), and denies an untagged session of the same role both."""
    ddb = ctx.client("dynamodb")
    iam = ctx.client("iam")
    caller = ctx.client("sts").get_caller_identity()
    partition = caller["Arn"].split(":")[1]
    account = caller["Account"]

    table = ctx.unique_name(f"{_PREFIX}pt-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"},
                   {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                              {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table(ddb, table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    table_arn = ddb.describe_table(TableName=table)["Table"]["TableArn"]
    for tenant in (TENANT_1, TENANT_2):
        ddb.put_item(TableName=table, Item={**_key(tenant, "seed"), "v": {"S": tenant}})

    role = ctx.unique_name(f"{_PREFIX}pt-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:{partition}:iam::{account}:root"},
        "Action": ["sts:AssumeRole", "sts:TagSession"],
    }]}
    role_arn = iam.create_role(
        RoleName=role, AssumeRolePolicyDocument=json.dumps(trust), Path="/",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role))
    iam.put_role_policy(RoleName=role, PolicyName="own-tenant", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query"],
            "Resource": table_arn,
            "Condition": {"ForAllValues:StringEquals": {
                "dynamodb:LeadingKeys": ["${aws:PrincipalTag/tenant}"]}},
        }],
    }))

    def admin_get(pk, sk):
        return ddb.get_item(TableName=table, Key=_key(pk, sk), ConsistentRead=True).get("Item")

    def assert_denied(op, fn, principal, action):
        code, msg = _denied(fn)
        assert code == ERR_ACCESS_DENIED, f"{op}: expected {ERR_ACCESS_DENIED!r}, got {code!r} ({msg!r})"
        assert IDENTITY_ATTRIBUTION in msg, (
            f"{op}: denial should be attributed to the identity policy, got {msg!r}"
        )
        expected_msg = (
            f"User: {principal} is not authorized to perform: dynamodb:{action} on resource: "
            f"{table_arn} because {IDENTITY_ATTRIBUTION} the dynamodb:{action} action"
        )
        assert msg == expected_msg, f"{op}: expected {expected_msg!r}, got {msg!r}"

    sessions = {TENANT_1: _tagged_client(ctx, role_arn, TENANT_1),
                TENANT_2: _tagged_client(ctx, role_arn, TENANT_2)}
    for me, other in ((TENANT_1, TENANT_2), (TENANT_2, TENANT_1)):
        s, principal = sessions[me]
        # Positive control: own partition, with the bounded retry at first use of the policy.
        got = _retry_denied(
            lambda: s.get_item(TableName=table, Key=_key(me, "seed"), ConsistentRead=True),
            description=f"GetItem by the {me} session on its own partition",
        )
        assert got.get("Item", {}).get("v") == {"S": me}, f"{me}: own read returned {got.get('Item')!r}"
        s.put_item(TableName=table, Item={**_key(me, "own"), "v": {"S": me}})
        assert admin_get(me, "own") == {**_key(me, "own"), "v": {"S": me}}, (
            f"{me}: own-partition PutItem did not land: {admin_get(me, 'own')!r}"
        )
        q = s.query(TableName=table, KeyConditionExpression="pk = :p",
                    ExpressionAttributeValues={":p": {"S": me}}, ConsistentRead=True)
        assert sorted(i["sk"]["S"] for i in q["Items"]) == ["own", "seed"], (
            f"{me}: own-partition Query returned {q['Items']!r}"
        )
        # The other tenant's partition: read, write and query all refused, write absent.
        assert_denied(f"GetItem({me} -> {other})",
                      lambda: s.get_item(TableName=table, Key=_key(other, "seed")),
                      principal, "GetItem")
        assert_denied(f"PutItem({me} -> {other})", lambda: s.put_item(
            TableName=table, Item={**_key(other, f"from-{me}"), "v": {"S": me}}),
            principal, "PutItem")
        assert admin_get(other, f"from-{me}") is None, (
            f"{me}: denied cross-tenant PutItem still wrote {admin_get(other, f'from-{me}')!r}"
        )
        assert_denied(f"Query({me} -> {other})", lambda: s.query(
            TableName=table, KeyConditionExpression="pk = :p",
            ExpressionAttributeValues={":p": {"S": other}}),
            principal, "Query")

    # An untagged session of the SAME role: the variable resolves to nothing, so nothing matches.
    untagged, untagged_principal = _tagged_client(ctx, role_arn, None)
    for tenant in (TENANT_1, TENANT_2):
        assert_denied(f"GetItem(untagged -> {tenant})",
                      lambda: untagged.get_item(TableName=table, Key=_key(tenant, "seed")),
                      untagged_principal, "GetItem")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
