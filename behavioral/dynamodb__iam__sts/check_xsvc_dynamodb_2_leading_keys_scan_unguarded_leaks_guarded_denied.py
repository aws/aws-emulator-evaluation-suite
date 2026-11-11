"""xsvc-dynamodb-2-leading-keys-scan-unguarded-leaks-guarded-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-dynamodb-2-leading-keys-scan-unguarded-leaks-guarded-denied"
GROUP = "overly_permissive"
SERVICES = ["dynamodb", "iam", "sts"]

ERR_ACCESS_DENIED = "AccessDeniedException"
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
    """Scan and key-less PartiQL SELECT carry no LeadingKeys, so ForAllValues alone lets them read all.

    That session is still denied GetItem on the other partition; adding a Null guard in the next
    session denies Scan and the SELECT while keyed reads on the allowed partition keep working.
    """
    ddb = ctx.client("dynamodb")
    iam = ctx.client("iam")
    caller = ctx.client("sts").get_caller_identity()
    partition = caller["Arn"].split(":")[1]
    account = caller["Account"]

    table = ctx.unique_name(f"{_PREFIX}lks-")
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

    role = ctx.unique_name(f"{_PREFIX}lks-")
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

    actions = ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan", "dynamodb:PartiQLSelect"]
    unguarded = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": actions, "Resource": table_arn,
        "Condition": {"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": [ALLOWED]}},
    }]}
    guarded = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": actions, "Resource": table_arn,
        "Condition": {"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": [ALLOWED]},
                      "Null": {"dynamodb:LeadingKeys": "false"}},
    }]}

    def scan_pks(client):
        pks, kw = [], {}
        while True:
            page = client.scan(TableName=table, ConsistentRead=True, **kw)
            pks += [i["pk"]["S"] for i in page["Items"]]
            if "LastEvaluatedKey" not in page:
                return sorted(pks)
            kw = {"ExclusiveStartKey": page["LastEvaluatedKey"]}

    def assert_denied(op, fn, principal, action):
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

    # --- Session 1: ForAllValues only ---------------------------------------------------------
    u, u_principal = _session_client(ctx, role_arn, unguarded)
    got = _retry_denied(
        lambda: u.get_item(TableName=table, Key=_key(ALLOWED, "seed"), ConsistentRead=True),
        timeout_s=_budget_s(ctx, 90.0),
        description="GetItem on the allowed partition (unguarded session)",
    )
    assert got.get("Item", {}).get("v") == {"S": f"{ALLOWED}-seed"}, f"got {got.get('Item')!r}"
    # The LeadingKeys condition is live in this session ...
    assert_denied("GetItem(other, unguarded)",
                  lambda: u.get_item(TableName=table, Key=_key(OTHER, "seed")),
                  u_principal, "GetItem")
    # ... and yet a Scan, which carries no LeadingKeys, sees both partitions: ForAllValues over
    # an absent key evaluates TRUE.
    leaked = scan_pks(u)
    assert leaked == [ALLOWED, OTHER], (
        f"an unguarded ForAllValues LeadingKeys session should Scan every partition "
        f"(empty-set semantics), got pks {leaked!r}"
    )
    full = u.execute_statement(Statement=f'SELECT * FROM "{table}"', ConsistentRead=True)
    assert sorted(i["pk"]["S"] for i in full["Items"]) == [ALLOWED, OTHER], (
        f"an unguarded key-less PartiQL SELECT should return every partition, got {full['Items']!r}"
    )

    # --- Session 2: same role, ForAllValues + Null guard --------------------------------------
    g, g_principal = _session_client(ctx, role_arn, guarded)
    got = g.get_item(TableName=table, Key=_key(ALLOWED, "seed"), ConsistentRead=True)
    assert got.get("Item", {}).get("v") == {"S": f"{ALLOWED}-seed"}, (
        f"guarded session lost the allowed partition: {got.get('Item')!r}"
    )
    q = g.query(TableName=table, KeyConditionExpression="pk = :p",
                ExpressionAttributeValues={":p": {"S": ALLOWED}}, ConsistentRead=True)
    assert [i["pk"]["S"] for i in q["Items"]] == [ALLOWED], f"guarded Query returned {q['Items']!r}"
    assert_denied("Scan(guarded)", lambda: g.scan(TableName=table), g_principal, "Scan")
    assert_denied("ExecuteStatement(key-less SELECT, guarded)",
                  lambda: g.execute_statement(Statement=f'SELECT * FROM "{table}"'),
                  g_principal, "PartiQLSelect")
    assert_denied("GetItem(other, guarded)",
                  lambda: g.get_item(TableName=table, Key=_key(OTHER, "seed")),
                  g_principal, "GetItem")

    # --- invariant: the table really holds both partitions (the leak was real data) -----------
    assert scan_pks(ddb) == [ALLOWED, OTHER], f"table contents changed: {scan_pks(ddb)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
