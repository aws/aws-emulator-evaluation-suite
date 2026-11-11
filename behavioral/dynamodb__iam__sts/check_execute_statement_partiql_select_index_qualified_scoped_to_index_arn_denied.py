"""execute-statement-partiql-select-index-qualified-scoped-to-index-arn-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-statement-partiql-select-index-qualified-scoped-to-index-arn-denied"
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
    """A table-ARN PartiQLSelect grant lets an unqualified ExecuteStatement SELECT succeed but denies
    the same SELECT qualified by the table's index; an index-ARN grant reverses which succeeds.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-iam.html
    """
    ddb = ctx.client("dynamodb")
    iam = ctx.client("iam")
    caller = ctx.client("sts").get_caller_identity()
    partition = caller["Arn"].split(":")[1]
    account = caller["Account"]

    table = ctx.unique_name("sim2real-xsvc-ddbql-ix-")
    index_name = "gsi1"
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "gsi_pk", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": index_name,
            "KeySchema": [{"AttributeName": "gsi_pk", "KeyType": "HASH"}],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table),
                             "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 1, "MaxAttempts": 60})

    deadline = time.monotonic() + 120.0
    while True:
        desc = ddb.describe_table(TableName=table)["Table"]
        gsi_statuses = {g["IndexName"]: g["IndexStatus"] for g in desc.get("GlobalSecondaryIndexes", [])}
        if gsi_statuses.get(index_name) == "ACTIVE":
            break
        assert time.monotonic() < deadline, f"index never became ACTIVE: {gsi_statuses!r}"
        time.sleep(2)
    table_arn = desc["TableArn"]
    index_arn = f"{table_arn}/index/{index_name}"

    ddb.put_item(TableName=table, Item={"pk": {"S": "seed"}, "gsi_pk": {"S": "seed"}})

    role_table = ctx.unique_name("sim2real-xsvc-ddbql-ixt-")
    role_index = ctx.unique_name("sim2real-xsvc-ddbql-ixi-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:{partition}:iam::{account}:root"},
        "Action": "sts:AssumeRole",
    }]}

    role_table_arn = iam.create_role(
        RoleName=role_table, AssumeRolePolicyDocument=json.dumps(trust), Path="/",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_table), "NoSuchEntity"))
    policy_table = "partiql-select-table-arn-only"
    iam.put_role_policy(RoleName=role_table, PolicyName=policy_table, PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Action": "dynamodb:PartiQLSelect", "Resource": table_arn,
        }],
    }))
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=role_table, PolicyName=policy_table), "NoSuchEntity"))

    role_index_arn = iam.create_role(
        RoleName=role_index, AssumeRolePolicyDocument=json.dumps(trust), Path="/",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_index), "NoSuchEntity"))
    policy_index = "partiql-select-index-arn-only"
    iam.put_role_policy(RoleName=role_index, PolicyName=policy_index, PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Action": "dynamodb:PartiQLSelect", "Resource": index_arn,
        }],
    }))
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=role_index, PolicyName=policy_index), "NoSuchEntity"))

    sts = ctx.client("sts")

    def _assume_role(role_arn):
        assume_not_yet = {(
            "AccessDenied",
            f"User: {caller['Arn']} is not authorized to perform: sts:AssumeRole on resource: {role_arn}",
        )}
        return _retry_denied(
            lambda: sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName=ctx.unique_name("sim2real-ddbql-")[:64],
                DurationSeconds=3600,
            ),
            assume_not_yet,
            timeout_s=90.0,
            description="sts:AssumeRole on the freshly created role",
        )

    def _client_for(assumed):
        creds = assumed["Credentials"]
        return ctx.client(
            "dynamodb",
            creds={
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds["SessionToken"],
            },
        ), assumed["AssumedRoleUser"]["Arn"]

    def _denied(principal, action, resource_arn):
        return (
            "AccessDeniedException",
            f"User: {principal} is not authorized to perform: {action} on resource: "
            f"{resource_arn} because no identity-based policy allows the {action} action",
        )

    # Table-ARN-scoped role: unqualified SELECT succeeds, the index-qualified SELECT is denied
    # naming the index's own ARN.
    assumed_t = _assume_role(role_table_arn)
    s_t, principal_t = _client_for(assumed_t)
    _table_denied_t = _denied(principal_t, "dynamodb:PartiQLSelect", table_arn)
    _index_denied_t = _denied(principal_t, "dynamodb:PartiQLSelect", index_arn)

    unqualified = _retry_denied(
        lambda: s_t.execute_statement(Statement=f"SELECT * FROM \"{table}\" WHERE pk = ?",
                                       Parameters=[{"S": "seed"}]),
        {_TOKEN_NOT_YET, _SESSION_NOT_YET, _table_denied_t},
        timeout_s=90.0,
        description="unqualified SELECT under the table-ARN-scoped policy",
    )
    assert unqualified["Items"] == [{"pk": {"S": "seed"}, "gsi_pk": {"S": "seed"}}], (
        f"unexpected unqualified SELECT result: {unqualified['Items']!r}"
    )
    expect_error(lambda: s_t.execute_statement(
        Statement=f"SELECT * FROM \"{table}\".\"{index_name}\" WHERE gsi_pk = ?",
        Parameters=[{"S": "seed"}]), *_index_denied_t)

    # Index-ARN-scoped role: the index-qualified SELECT succeeds, the unqualified one on the
    # table itself is denied naming the table's own ARN.
    assumed_i = _assume_role(role_index_arn)
    s_i, principal_i = _client_for(assumed_i)
    _table_denied_i = _denied(principal_i, "dynamodb:PartiQLSelect", table_arn)
    _index_denied_i = _denied(principal_i, "dynamodb:PartiQLSelect", index_arn)

    qualified = _retry_denied(
        lambda: s_i.execute_statement(
            Statement=f"SELECT * FROM \"{table}\".\"{index_name}\" WHERE gsi_pk = ?",
            Parameters=[{"S": "seed"}]),
        {_TOKEN_NOT_YET, _SESSION_NOT_YET, _index_denied_i},
        timeout_s=90.0,
        description="index-qualified SELECT under the index-ARN-scoped policy",
    )
    assert qualified["Items"] == [{"pk": {"S": "seed"}, "gsi_pk": {"S": "seed"}}], (
        f"unexpected index-qualified SELECT result: {qualified['Items']!r}"
    )
    expect_error(lambda: s_i.execute_statement(Statement=f"SELECT * FROM \"{table}\" WHERE pk = ?",
                                                Parameters=[{"S": "seed"}]), *_table_denied_i)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
