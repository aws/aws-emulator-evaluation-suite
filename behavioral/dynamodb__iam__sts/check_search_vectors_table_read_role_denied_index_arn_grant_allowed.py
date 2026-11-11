"""search-vectors-table-read-role-denied-index-arn-grant-allowed."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "search-vectors-table-read-role-denied-index-arn-grant-allowed"
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
    """SearchVectors needs dynamodb:SearchVectors granted on the vector index's own ARN: a role
    holding only GetItem/Query/Scan on the table is denied, and the same role succeeds once that
    action is granted on the index ARN.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/vector-search.html
    """
    ddb = ctx.client("dynamodb")
    iam = ctx.client("iam")
    caller = ctx.client("sts").get_caller_identity()
    partition = caller["Arn"].split(":")[1]
    account = caller["Account"]

    table = ctx.unique_name("sim2real-vecgsi-")
    index_name = "vec-idx"
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        VectorIndexes=[{
            "IndexName": index_name,
            "VectorAttribute": {"AttributeName": "embedding"},
            "Dimensions": 3,
            "DistanceFunction": "COSINE",
            "Projection": {"ProjectionType": "ALL"},
        }],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table),
                             "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    described = ddb.describe_table(TableName=table)["Table"]
    vector_indexes = described.get("VectorIndexes", [])
    assert vector_indexes, "CreateTable accepted VectorIndexes but DescribeTable reports none"
    deadline = time.monotonic() + 120
    while vector_indexes[0].get("IndexStatus") != "ACTIVE" and time.monotonic() < deadline:
        time.sleep(2)
        vector_indexes = ddb.describe_table(TableName=table)["Table"]["VectorIndexes"]
        assert vector_indexes, "the vector index disappeared while it was backfilling"
    assert vector_indexes[0].get("IndexStatus") == "ACTIVE", (
        f"the vector index never became ACTIVE: {vector_indexes[0].get('IndexStatus')!r}"
    )
    table_arn = described["TableArn"]
    index_arn = vector_indexes[0]["IndexArn"]

    vector = [{"N": "0.1"}, {"N": "0.2"}, {"N": "0.3"}]
    ddb.put_item(TableName=table, Item={"pk": {"S": "item-1"}, "embedding": {"L": vector}})

    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:{partition}:iam::{account}:root"},
        "Action": "sts:AssumeRole",
    }]}
    read_only_statement = {
        "Effect": "Allow",
        "Action": ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan"],
        "Resource": table_arn,
    }

    def _make_role(name_prefix, statements):
        name = ctx.unique_name(name_prefix)
        arn = iam.create_role(
            RoleName=name, AssumeRolePolicyDocument=json.dumps(trust), Path="/",
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )["Role"]["Arn"]
        ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
        iam.put_role_policy(RoleName=name, PolicyName="policy", PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": statements,
        }))
        ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(RoleName=name, PolicyName="policy"),
                                 "NoSuchEntity"))
        return name, arn

    denied_role, denied_role_arn = _make_role("sim2real-vecgsi-denied-", [read_only_statement])
    allowed_role, allowed_role_arn = _make_role("sim2real-vecgsi-allowed-", [
        read_only_statement,
        {"Effect": "Allow", "Action": "dynamodb:SearchVectors", "Resource": index_arn},
    ])

    sts = ctx.client("sts")

    def _assume(role_arn):
        not_yet = {(
            "AccessDenied",
            f"User: {caller['Arn']} is not authorized to perform: sts:AssumeRole on resource: {role_arn}",
        )}
        assumed = _retry_denied(
            lambda: sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName=ctx.unique_name("sim2real-vecgsi-")[:64],
                DurationSeconds=3600,
            ),
            not_yet,
            timeout_s=90.0,
            description=f"sts:AssumeRole on {role_arn}",
        )
        creds = assumed["Credentials"]
        principal = assumed["AssumedRoleUser"]["Arn"]
        client = ctx.client(
            "dynamodb",
            creds={
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds["SessionToken"],
            },
        )
        return client, principal

    _token_not_yet = ("InvalidClientTokenId", "The security token included in the request is invalid.")

    s_denied, denied_principal = _assume(denied_role_arn)

    _denied_get_item = (
        "AccessDeniedException",
        f"User: {denied_principal} is not authorized to perform: dynamodb:GetItem on resource: "
        f"{table_arn} because no identity-based policy allows the dynamodb:GetItem action",
    )
    # Positive control: the table-read-only role can read the table it was scoped to -- the
    # denial below is specific to SearchVectors, not a propagation failure or a broken role.
    got = _retry_denied(
        lambda: s_denied.get_item(TableName=table, Key={"pk": {"S": "item-1"}}, ConsistentRead=True),
        {_token_not_yet, _denied_get_item},
        timeout_s=90.0,
        description="GetItem under the table-read-only role",
    )
    assert got.get("Item") == {"pk": {"S": "item-1"}, "embedding": {"L": vector}}, (
        f"GetItem under the read-only role returned an unexpected item: {got.get('Item')!r}"
    )

    _denied_search_vectors = (
        "AccessDeniedException",
        f"User: {denied_principal} is not authorized to perform: dynamodb:SearchVectors on resource: "
        f"{index_arn} because no identity-based policy allows the dynamodb:SearchVectors action",
    )
    expect_error(
        lambda: s_denied.search_vectors(TableName=table, IndexName=index_name, SearchVector=vector, TopK=1),
        *_denied_search_vectors,
    )

    # A role granted dynamodb:SearchVectors scoped to the index's own ARN succeeds, proving the
    # denial above is the dedicated-grant rule and not a broken role or vector index.
    s_allowed, allowed_principal = _assume(allowed_role_arn)
    _denied_search_vectors_allowed_role = (
        "AccessDeniedException",
        f"User: {allowed_principal} is not authorized to perform: dynamodb:SearchVectors on resource: "
        f"{index_arn} because no identity-based policy allows the dynamodb:SearchVectors action",
    )
    results = _retry_denied(
        lambda: s_allowed.search_vectors(TableName=table, IndexName=index_name, SearchVector=vector, TopK=1)[
            "SearchResults"
        ],
        {_token_not_yet, _denied_search_vectors_allowed_role},
        timeout_s=90.0,
        description="SearchVectors under the role granted dynamodb:SearchVectors on the index ARN",
    )
    assert len(results) == 1, f"expected exactly 1 search result, got {results!r}"
    assert results[0]["Item"] == {"pk": {"S": "item-1"}}, (
        f"SearchVectors returned an unexpected item: {results[0].get('Item')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
