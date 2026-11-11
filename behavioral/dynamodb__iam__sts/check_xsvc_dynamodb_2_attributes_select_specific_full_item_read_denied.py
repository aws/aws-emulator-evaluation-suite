"""xsvc-dynamodb-2-attributes-select-specific-full-item-read-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-dynamodb-2-attributes-select-specific-full-item-read-denied"
GROUP = "overly_permissive"
SERVICES = ["dynamodb", "iam", "sts"]

ERR_ACCESS_DENIED = "AccessDeniedException"
SESSION_ATTRIBUTION = "no session policy allows"

ALLOWED = "tenant-allowed"
OTHER = "tenant-other"
VISIBLE = ["pk", "sk", "pub"]

_PREFIX = "sim2real-xsvc-"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _denied(fn):
    """Call fn(); return (code, message) of the ClientError it raises, or raise if it succeeds."""
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


def _session_client(ctx, role_arn, session_policy):
    """A DynamoDB client for a fresh session of ``role_arn``, and the session's principal ARN."""
    sts = ctx.client("sts")
    assumed = _retry_denied(
        lambda: sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=ctx.unique_name("sim2real-lk-")[:64],
            Policy=json.dumps(session_policy),
            DurationSeconds=3600,
        ),
        timeout_s=_budget_s(ctx, 90.0),
        description="sts:AssumeRole on the freshly created role",
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
    """A session policy on dynamodb:Attributes and Select=SPECIFIC_ATTRIBUTES allows only projections.

    Projected GetItem, Query and BatchGetItem succeed; full reads, a hidden-attribute projection
    and Select=ALL_ATTRIBUTES are AccessDeniedException, and the stored item is unchanged.
    """
    ddb = ctx.client("dynamodb")
    iam = ctx.client("iam")
    caller = ctx.client("sts").get_caller_identity()
    partition = caller["Arn"].split(":")[1]
    account = caller["Account"]

    table = ctx.unique_name(f"{_PREFIX}attr-")
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
    full_item = {**_key(ALLOWED, "1"), "pub": {"S": "public-value"}, "secret": {"S": "hidden-value"}}
    ddb.put_item(TableName=table, Item=full_item)
    ddb.put_item(TableName=table, Item={**_key(OTHER, "1"), "pub": {"S": "p"}, "secret": {"S": "s"}})

    role = ctx.unique_name(f"{_PREFIX}attr-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:{partition}:iam::{account}:root"},
        "Action": "sts:AssumeRole",
    }]}
    role_arn = iam.create_role(
        RoleName=role, AssumeRolePolicyDocument=json.dumps(trust), Path="/",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role))
    iam.put_role_policy(RoleName=role, PolicyName="table-all", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "dynamodb:*", "Resource": table_arn}],
    }))

    # A ProjectionExpression with no Select satisfies StringEquals on dynamodb:Select: AWS derives
    # the Select and Attributes condition keys from the request itself.
    session_policy = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow",
        "Action": ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:BatchGetItem"],
        "Resource": table_arn,
        "Condition": {
            "ForAllValues:StringEquals": {"dynamodb:LeadingKeys": [ALLOWED],
                                          "dynamodb:Attributes": VISIBLE},
            "StringEquals": {"dynamodb:Select": "SPECIFIC_ATTRIBUTES"},
        },
    }]}
    s, principal = _session_client(ctx, role_arn, session_policy)
    proj = "pk, sk, pub"
    visible_item = {k: v for k, v in full_item.items() if k in VISIBLE}

    def assert_denied(op, fn, action):
        code, msg = _denied(fn)
        assert code == ERR_ACCESS_DENIED, f"{op}: expected {ERR_ACCESS_DENIED!r}, got {code!r} ({msg!r})"
        assert SESSION_ATTRIBUTION in msg, (
            f"{op}: denial should be attributed to the session policy, got {msg!r}"
        )
        expected_msg = (
            f"User: {principal} is not authorized to perform: dynamodb:{action} on resource: "
            f"{table_arn} because {SESSION_ATTRIBUTION} the dynamodb:{action} action"
        )
        assert msg == expected_msg, f"{op}: expected {expected_msg!r}, got {msg!r}"

    # --- GetItem: projected read allowed (positive control), full read denied ----------------
    got = _retry_denied(
        lambda: s.get_item(TableName=table, Key=_key(ALLOWED, "1"), ProjectionExpression=proj,
                           ConsistentRead=True),
        timeout_s=_budget_s(ctx, 90.0),
        description="projected GetItem on the allowed partition",
    )
    assert got.get("Item") == visible_item, (
        f"projected GetItem returned {got.get('Item')!r}, expected exactly {visible_item!r}"
    )
    assert_denied("GetItem(full item)", lambda: s.get_item(TableName=table, Key=_key(ALLOWED, "1")), "GetItem")
    assert_denied("GetItem(projects hidden attribute)", lambda: s.get_item(
        TableName=table, Key=_key(ALLOWED, "1"), ProjectionExpression="pk, secret"), "GetItem")
    assert_denied("GetItem(projected, other partition)", lambda: s.get_item(
        TableName=table, Key=_key(OTHER, "1"), ProjectionExpression=proj), "GetItem")

    # --- Query: Select=SPECIFIC_ATTRIBUTES allowed, ALL_ATTRIBUTES / default denied ----------
    q = s.query(TableName=table, KeyConditionExpression="pk = :p",
                ExpressionAttributeValues={":p": {"S": ALLOWED}}, Select="SPECIFIC_ATTRIBUTES",
                ProjectionExpression="pk, pub", ConsistentRead=True)
    assert q["Items"] == [{"pk": {"S": ALLOWED}, "pub": {"S": "public-value"}}], (
        f"projected Query returned {q['Items']!r}"
    )
    assert_denied("Query(Select=ALL_ATTRIBUTES)", lambda: s.query(
        TableName=table, KeyConditionExpression="pk = :p",
        ExpressionAttributeValues={":p": {"S": ALLOWED}}, Select="ALL_ATTRIBUTES"), "Query")
    assert_denied("Query(no projection)", lambda: s.query(
        TableName=table, KeyConditionExpression="pk = :p",
        ExpressionAttributeValues={":p": {"S": ALLOWED}}), "Query")

    # --- BatchGetItem: projected allowed, full denied ----------------------------------------
    bg = s.batch_get_item(RequestItems={table: {"Keys": [_key(ALLOWED, "1")],
                                                "ProjectionExpression": proj,
                                                "ConsistentRead": True}})
    assert bg["Responses"].get(table) == [visible_item], (
        f"projected BatchGetItem returned {bg['Responses']!r}"
    )
    assert_denied("BatchGetItem(full item)", lambda: s.batch_get_item(
        RequestItems={table: {"Keys": [_key(ALLOWED, "1")]}}), "BatchGetItem")

    # --- invariant: the hidden attribute was never removed, only hidden ----------------------
    stored = ddb.get_item(TableName=table, Key=_key(ALLOWED, "1"), ConsistentRead=True).get("Item")
    assert stored == full_item, f"the stored item changed: {stored!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
