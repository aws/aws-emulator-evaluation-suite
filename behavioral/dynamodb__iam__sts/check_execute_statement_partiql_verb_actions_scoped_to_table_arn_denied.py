"""execute-statement-partiql-verb-actions-scoped-to-table-arn-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-statement-partiql-verb-actions-scoped-to-table-arn-denied"
GROUP = "overly_permissive"
SERVICES = ["dynamodb", "iam", "sts"]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """(code, message) of the ClientError fn() raises; raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    result = {k: v for k, v in (result or {}).items() if k != "ResponseMetadata"}
    raise AssertionError(f"call was expected to be DENIED but succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code!r}, got {got_code!r} ({got_message!r})"
    assert got_message == message, f"unexpected message {got_message!r}"


_TOKEN_NOT_YET = ("InvalidClientTokenId", "The security token included in the request is invalid.")
_SESSION_NOT_YET = ("UnrecognizedClientException", "The security token included in the request is invalid.")


def _retry_denied(fn, not_yet, *, timeout_s=90.0, interval_s=3.0, description="call"):
    """Retry fn() only while it raises one of the exact ``not_yet`` (code, message) pairs that
    IAM role/policy propagation answers; the bounded retry at first use IS the wait."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            pair = (err.get("Code"), err.get("Message"))
            if pair not in not_yet or time.monotonic() >= deadline:
                raise AssertionError(
                    f"{description} failed with {err.get('Code')!r}: {err.get('Message')!r}"
                ) from exc
        time.sleep(interval_s)


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A policy granting PartiQLSelect and PartiQLInsert on one table's ARN allows ExecuteStatement
    SELECT and INSERT there, denies PartiQLUpdate and PartiQLDelete on the same table, and denies
    PartiQLSelect on a second table the grant never named.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-iam.html
    """
    ddb = ctx.client("dynamodb")
    iam = ctx.client("iam")
    caller = ctx.client("sts").get_caller_identity()
    partition = caller["Arn"].split(":")[1]
    account = caller["Account"]

    table_a = ctx.unique_name("sim2real-xsvc-ddbql-a-")
    ddb.create_table(
        TableName=table_a,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table_a),
                             "ResourceNotFoundException"))

    table_b = ctx.unique_name("sim2real-xsvc-ddbql-b-")
    ddb.create_table(
        TableName=table_b,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table_b),
                             "ResourceNotFoundException"))

    ddb.get_waiter("table_exists").wait(TableName=table_a, WaiterConfig={"Delay": 1, "MaxAttempts": 60})
    ddb.get_waiter("table_exists").wait(TableName=table_b, WaiterConfig={"Delay": 1, "MaxAttempts": 60})
    table_a_arn = ddb.describe_table(TableName=table_a)["Table"]["TableArn"]
    table_b_arn = ddb.describe_table(TableName=table_b)["Table"]["TableArn"]

    ddb.put_item(TableName=table_a, Item={"pk": {"S": "seed"}})
    ddb.put_item(TableName=table_b, Item={"pk": {"S": "seed"}})

    role = ctx.unique_name("sim2real-xsvc-ddbql-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:{partition}:iam::{account}:root"},
        "Action": "sts:AssumeRole",
    }]}
    role_arn = iam.create_role(
        RoleName=role, AssumeRolePolicyDocument=json.dumps(trust), Path="/",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role), "NoSuchEntity"))
    policy_name = "partiql-select-insert-table-a-only"
    iam.put_role_policy(RoleName=role, PolicyName=policy_name, PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["dynamodb:PartiQLSelect", "dynamodb:PartiQLInsert"],
            "Resource": table_a_arn,
        }],
    }))
    ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(RoleName=role, PolicyName=policy_name),
                             "NoSuchEntity"))

    sts = ctx.client("sts")
    assume_not_yet = {(
        "AccessDenied",
        f"User: {caller['Arn']} is not authorized to perform: sts:AssumeRole on resource: {role_arn}",
    )}
    assumed = _retry_denied(
        lambda: sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=ctx.unique_name("sim2real-ddbql-")[:64],
            DurationSeconds=3600,
        ),
        assume_not_yet,
        timeout_s=90.0,
        description="sts:AssumeRole on the freshly created role",
    )
    creds = assumed["Credentials"]
    principal = assumed["AssumedRoleUser"]["Arn"]
    s = ctx.client(
        "dynamodb",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    def _denied(action: str, resource_arn: str):
        return (
            "AccessDeniedException",
            f"User: {principal} is not authorized to perform: {action} on resource: "
            f"{resource_arn} because no identity-based policy allows the {action} action",
        )

    _select_a_denied = _denied("dynamodb:PartiQLSelect", table_a_arn)
    _insert_a_denied = _denied("dynamodb:PartiQLInsert", table_a_arn)
    _update_a_denied = _denied("dynamodb:PartiQLUpdate", table_a_arn)
    _delete_a_denied = _denied("dynamodb:PartiQLDelete", table_a_arn)
    _select_b_denied = _denied("dynamodb:PartiQLSelect", table_b_arn)

    # The granted verb on the granted table: retried once against the exact denial IAM and
    # session-token propagation answer before the credentials and inline policy take effect.
    select_result = _retry_denied(
        lambda: s.execute_statement(Statement=f"SELECT * FROM \"{table_a}\" WHERE pk = ?",
                                     Parameters=[{"S": "seed"}]),
        {_TOKEN_NOT_YET, _SESSION_NOT_YET, _select_a_denied},
        timeout_s=90.0,
        description="SELECT on table A under the table-A-scoped policy",
    )
    assert select_result["Items"] == [{"pk": {"S": "seed"}}], (
        f"unexpected SELECT result: {select_result['Items']!r}"
    )

    _retry_denied(
        lambda: s.execute_statement(
            Statement=f"INSERT INTO \"{table_a}\" VALUE {{'pk': ?}}", Parameters=[{"S": "inserted"}]),
        {_TOKEN_NOT_YET, _SESSION_NOT_YET, _insert_a_denied},
        timeout_s=90.0,
        description="INSERT on table A under the table-A-scoped policy",
    )
    written = ddb.get_item(TableName=table_a, Key={"pk": {"S": "inserted"}}, ConsistentRead=True).get("Item")
    assert written == {"pk": {"S": "inserted"}}, f"granted INSERT did not land: {written!r}"

    # The same table, verbs the policy never grants: denied regardless of propagation state.
    expect_error(lambda: s.execute_statement(
        Statement=f"UPDATE \"{table_a}\" SET extra = ? WHERE pk = ?",
        Parameters=[{"S": "x"}, {"S": "seed"}]), *_update_a_denied)
    unchanged = ddb.get_item(TableName=table_a, Key={"pk": {"S": "seed"}}, ConsistentRead=True)["Item"]
    assert "extra" not in unchanged, f"a denied UPDATE wrote extra: {unchanged!r}"

    expect_error(lambda: s.execute_statement(
        Statement=f"DELETE FROM \"{table_a}\" WHERE pk = ?", Parameters=[{"S": "seed"}]),
        *_delete_a_denied)
    still_there = ddb.get_item(TableName=table_a, Key={"pk": {"S": "seed"}}, ConsistentRead=True).get("Item")
    assert still_there == {"pk": {"S": "seed"}}, f"a denied DELETE removed the item: {still_there!r}"

    # A different table: the grant on table A's ARN confers nothing on table B.
    expect_error(lambda: s.execute_statement(
        Statement=f"SELECT * FROM \"{table_b}\" WHERE pk = ?", Parameters=[{"S": "seed"}]),
        *_select_b_denied)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
