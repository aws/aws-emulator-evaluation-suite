"""xsvc-dynamodb-2-leading-keys-session-policy-other-partition-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-dynamodb-2-leading-keys-session-policy-other-partition-denied"
GROUP = "overly_permissive"
SERVICES = ["dynamodb", "iam", "sts"]

ERR_ACCESS_DENIED = "AccessDeniedException"
# With a dynamodb:* identity policy, AWS attributes a LeadingKeys mismatch to the SESSION policy;
# asserted so a denial raised by some other layer cannot satisfy the leg.
SESSION_ATTRIBUTION = "no session policy allows"

ALLOWED = "tenant-allowed"
OTHER = "tenant-other"

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
    """A LeadingKeys session policy confines one session to one partition across item and PartiQL APIs.

    The allowed key's reads and writes succeed and land; the other key, or any batch or transaction
    that includes it, is AccessDeniedException and writes nothing.
    """
    ddb = ctx.client("dynamodb")
    iam = ctx.client("iam")
    caller = ctx.client("sts").get_caller_identity()
    partition = caller["Arn"].split(":")[1]
    account = caller["Account"]

    table = ctx.unique_name(f"{_PREFIX}lk-")
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

    for pk in (ALLOWED, OTHER):
        ddb.put_item(TableName=table, Item={**_key(pk, "seed"), "v": {"S": f"{pk}-seed"}})

    role = ctx.unique_name(f"{_PREFIX}lk-")
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
    # The identity policy is deliberately BROAD: every narrowing below comes from the session.
    iam.put_role_policy(RoleName=role, PolicyName="table-all", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "dynamodb:*", "Resource": table_arn}],
    }))

    session_policy = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow",
        "Action": ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:BatchGetItem",
                   "dynamodb:BatchWriteItem", "dynamodb:PutItem", "dynamodb:TransactWriteItems",
                   "dynamodb:PartiQLSelect", "dynamodb:PartiQLInsert"],
        "Resource": table_arn,
        # The Null guard closes key-less reads, which ForAllValues alone would allow.
        "Condition": {
            "ForAllValues:StringEquals": {"dynamodb:LeadingKeys": [ALLOWED]},
            "Null": {"dynamodb:LeadingKeys": "false"},
        },
    }]}
    s, principal = _session_client(ctx, role_arn, session_policy)

    def admin_get(pk, sk):
        return ddb.get_item(TableName=table, Key=_key(pk, sk), ConsistentRead=True).get("Item")

    def assert_denied(op, fn, action):
        code, msg = _denied(fn)
        assert code == ERR_ACCESS_DENIED, (
            f"{op} on partition {OTHER!r} expected {ERR_ACCESS_DENIED!r}, got {code!r} ({msg!r})"
        )
        assert SESSION_ATTRIBUTION in msg, (
            f"{op} denial should be attributed to the session policy "
            f"(substring {SESSION_ATTRIBUTION!r}), got {msg!r}"
        )
        expected_msg = (
            f"User: {principal} is not authorized to perform: dynamodb:{action} on resource: "
            f"{table_arn} because {SESSION_ATTRIBUTION} the dynamodb:{action} action"
        )
        assert msg == expected_msg, f"{op}: expected {expected_msg!r}, got {msg!r}"

    # --- GetItem ------------------------------------------------------------------------------
    # Positive control first, with the bounded retry at first use of the role's permissions.
    got = _retry_denied(
        lambda: s.get_item(TableName=table, Key=_key(ALLOWED, "seed"), ConsistentRead=True),
        timeout_s=_budget_s(ctx, 90.0),
        description="GetItem on the allowed partition",
    )
    assert got.get("Item", {}).get("v") == {"S": f"{ALLOWED}-seed"}, (
        f"GetItem on the allowed partition returned {got.get('Item')!r}"
    )
    assert_denied("GetItem", lambda: s.get_item(TableName=table, Key=_key(OTHER, "seed")), "GetItem")

    # --- Query --------------------------------------------------------------------------------
    q = s.query(TableName=table, KeyConditionExpression="pk = :p",
                ExpressionAttributeValues={":p": {"S": ALLOWED}}, ConsistentRead=True)
    assert [i["pk"]["S"] for i in q["Items"]] == [ALLOWED], (
        f"Query on the allowed partition returned {q['Items']!r}"
    )
    assert_denied("Query", lambda: s.query(
        TableName=table, KeyConditionExpression="pk = :p",
        ExpressionAttributeValues={":p": {"S": OTHER}}), "Query")

    # --- BatchGetItem -------------------------------------------------------------------------
    bg = s.batch_get_item(RequestItems={table: {"Keys": [_key(ALLOWED, "seed")],
                                                "ConsistentRead": True}})
    assert [i["v"]["S"] for i in bg["Responses"].get(table, [])] == [f"{ALLOWED}-seed"], (
        f"BatchGetItem on the allowed partition returned {bg['Responses']!r}"
    )
    assert_denied("BatchGetItem", lambda: s.batch_get_item(
        RequestItems={table: {"Keys": [_key(OTHER, "seed")]}}), "BatchGetItem")
    # One foreign key in the batch denies the WHOLE request, not just that key.
    assert_denied("BatchGetItem(mixed)", lambda: s.batch_get_item(
        RequestItems={table: {"Keys": [_key(ALLOWED, "seed"), _key(OTHER, "seed")]}}), "BatchGetItem")

    # --- BatchWriteItem -----------------------------------------------------------------------
    bw = s.batch_write_item(RequestItems={table: [
        {"PutRequest": {"Item": {**_key(ALLOWED, "bw"), "v": {"S": "bw"}}}}]})
    assert not bw.get("UnprocessedItems"), f"BatchWriteItem left {bw['UnprocessedItems']!r}"
    assert admin_get(ALLOWED, "bw") == {**_key(ALLOWED, "bw"), "v": {"S": "bw"}}, (
        f"allowed BatchWriteItem did not land: {admin_get(ALLOWED, 'bw')!r}"
    )
    assert_denied("BatchWriteItem", lambda: s.batch_write_item(RequestItems={table: [
        {"PutRequest": {"Item": {**_key(OTHER, "bw"), "v": {"S": "bw"}}}}]}), "BatchWriteItem")
    assert admin_get(OTHER, "bw") is None, (
        f"denied BatchWriteItem still wrote {admin_get(OTHER, 'bw')!r}"
    )

    # --- TransactWriteItems -------------------------------------------------------------------
    s.transact_write_items(TransactItems=[
        {"Put": {"TableName": table, "Item": {**_key(ALLOWED, "tx"), "v": {"S": "tx"}}}}])
    assert admin_get(ALLOWED, "tx") == {**_key(ALLOWED, "tx"), "v": {"S": "tx"}}, (
        f"allowed TransactWriteItems did not land: {admin_get(ALLOWED, 'tx')!r}"
    )
    assert_denied("TransactWriteItems", lambda: s.transact_write_items(TransactItems=[
        {"Put": {"TableName": table, "Item": {**_key(OTHER, "tx"), "v": {"S": "tx"}}}}]), "PutItem")
    assert admin_get(OTHER, "tx") is None, (
        f"denied TransactWriteItems still wrote {admin_get(OTHER, 'tx')!r}"
    )
    # A transaction with one foreign item is refused as a unit: the allowed half must not land.
    assert_denied("TransactWriteItems(mixed)", lambda: s.transact_write_items(TransactItems=[
        {"Put": {"TableName": table, "Item": {**_key(ALLOWED, "txm"), "v": {"S": "txm"}}}},
        {"Put": {"TableName": table, "Item": {**_key(OTHER, "txm"), "v": {"S": "txm"}}}}]), "PutItem")
    assert admin_get(ALLOWED, "txm") is None, (
        f"a denied transaction partially applied: {admin_get(ALLOWED, 'txm')!r}"
    )

    # --- ExecuteStatement (PartiQL SELECT and INSERT) -----------------------------------------
    sel = s.execute_statement(Statement=f'SELECT * FROM "{table}" WHERE pk = ?',
                              Parameters=[{"S": ALLOWED}], ConsistentRead=True)
    assert sorted(i["sk"]["S"] for i in sel["Items"]) == ["bw", "seed", "tx"], (
        f"PartiQL SELECT on the allowed partition returned {sel['Items']!r}"
    )
    assert {i["pk"]["S"] for i in sel["Items"]} == {ALLOWED}, (
        f"PartiQL SELECT leaked another partition: {sel['Items']!r}"
    )
    assert_denied("ExecuteStatement(SELECT)", lambda: s.execute_statement(
        Statement=f'SELECT * FROM "{table}" WHERE pk = ?', Parameters=[{"S": OTHER}]), "PartiQLSelect")
    s.execute_statement(Statement=f"INSERT INTO \"{table}\" VALUE {{'pk': ?, 'sk': 'pq'}}",
                        Parameters=[{"S": ALLOWED}])
    assert admin_get(ALLOWED, "pq") == _key(ALLOWED, "pq"), (
        f"allowed PartiQL INSERT did not land: {admin_get(ALLOWED, 'pq')!r}"
    )
    assert_denied("ExecuteStatement(INSERT)", lambda: s.execute_statement(
        Statement=f"INSERT INTO \"{table}\" VALUE {{'pk': ?, 'sk': 'pq'}}",
        Parameters=[{"S": OTHER}]), "PartiQLInsert")
    assert admin_get(OTHER, "pq") is None, (
        f"denied PartiQL INSERT still wrote {admin_get(OTHER, 'pq')!r}"
    )

    # --- invariant: the foreign partition holds exactly its seed, untouched -------------------
    other_rows = ddb.query(TableName=table, KeyConditionExpression="pk = :p",
                           ExpressionAttributeValues={":p": {"S": OTHER}},
                           ConsistentRead=True)["Items"]
    assert other_rows == [{**_key(OTHER, "seed"), "v": {"S": f"{OTHER}-seed"}}], (
        f"the denied partition was modified: {other_rows!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
