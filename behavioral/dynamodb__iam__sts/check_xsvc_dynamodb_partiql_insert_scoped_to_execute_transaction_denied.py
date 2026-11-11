"""xsvc-dynamodb-partiql-insert-scoped-to-execute-transaction-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-dynamodb-partiql-insert-scoped-to-execute-transaction-denied"
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
    """An IAM policy granting dynamodb:PartiQLInsert only when
    dynamodb:EnclosingOperation=ExecuteTransaction denies a bare ExecuteStatement INSERT and
    writes nothing, while the identical INSERT inside ExecuteTransaction succeeds.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-iam.html
    """
    ddb = ctx.client("dynamodb")
    iam = ctx.client("iam")
    caller = ctx.client("sts").get_caller_identity()
    partition = caller["Arn"].split(":")[1]
    account = caller["Account"]

    table = ctx.unique_name("sim2real-xsvc-ddbql-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table),
                             "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 1, "MaxAttempts": 60})
    table_arn = ddb.describe_table(TableName=table)["Table"]["TableArn"]

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
    policy_name = "partiql-insert-select-txn-only"
    iam.put_role_policy(RoleName=role, PolicyName=policy_name, PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["dynamodb:PartiQLInsert", "dynamodb:PartiQLSelect"],
            "Resource": table_arn,
            "Condition": {"StringEquals": {"dynamodb:EnclosingOperation": "ExecuteTransaction"}},
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

    _bare_denied = (
        "AccessDeniedException",
        f"User: {principal} is not authorized to perform: dynamodb:PartiQLInsert on resource: "
        f"{table_arn} because no identity-based policy allows the dynamodb:PartiQLInsert action",
    )

    # The identical INSERT, enclosed in ExecuteTransaction, matches the condition and succeeds --
    # bounded-retried against IAM propagation, the same way the role's trust was.
    _retry_denied(
        lambda: s.execute_transaction(TransactStatements=[{
            "Statement": f"INSERT INTO \"{table}\" VALUE {{'pk': ?}}", "Parameters": [{"S": "txn"}],
        }]),
        {_TOKEN_NOT_YET, _bare_denied},
        timeout_s=90.0,
        description="ExecuteTransaction INSERT under the ExecuteTransaction-only policy",
    )

    # A bare ExecuteStatement INSERT has no enclosing ExecuteTransaction, so the condition never
    # matches and the identity policy grants nothing else: the call is denied unconditionally.
    expect_error(lambda: s.execute_statement(
        Statement=f"INSERT INTO \"{table}\" VALUE {{'pk': ?}}", Parameters=[{"S": "bare"}]), *_bare_denied)
    assert ddb.get_item(TableName=table, Key={"pk": {"S": "bare"}}, ConsistentRead=True).get("Item") is None, (
        "a denied bare ExecuteStatement INSERT wrote an item"
    )
    written = ddb.get_item(TableName=table, Key={"pk": {"S": "txn"}}, ConsistentRead=True).get("Item")
    assert written == {"pk": {"S": "txn"}}, f"ExecuteTransaction INSERT did not land: {written!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
