"""describetable-tablename-wrong-json-type-rejected."""
from __future__ import annotations

import json
import time

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describetable-tablename-wrong-json-type-rejected"
GROUP = "control-plane-type-validation-rejected"
SERVICES = ["dynamodb"]

_RNF = "ResourceNotFoundException"
_SER = "SerializationException"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _await_table_active(ctx, ddb, table: str) -> None:
    """Poll DescribeTable every second until the table is ACTIVE, bounded by the budget."""
    deadline = time.time() + _budget_s(ctx, 300.0)
    status = None
    while True:
        status = ddb.describe_table(TableName=table)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return
        if time.time() >= deadline and _budget_spent(ctx):
            raise TimeoutError(f"table {table!r} ACTIVE: the run budget ended first; not graded")
        assert time.time() < deadline, f"table {table!r} never reached ACTIVE (last {status!r})"
        time.sleep(1.0)


def _absent_ok(fn) -> None:
    """Failure-path teardown for a resource the success path already deleted."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """DescribeTable refuses a TableName whose raw JSON type is not a string with
    SerializationException naming the offending JSON token, before any table lookup.
    """
    import urllib3

    ddb = ctx.client("dynamodb")
    endpoint = ddb.meta.endpoint_url
    raw_creds = ddb._request_signer._credentials
    frozen = (raw_creds.get_frozen_credentials()
              if hasattr(raw_creds, "get_frozen_credentials") else raw_creds)
    verify = ctx.http_verify
    pool = urllib3.PoolManager(cert_reqs="CERT_REQUIRED" if verify else "CERT_NONE",
                               ca_certs=verify if isinstance(verify, str) else None)

    def raw(table_name_value):
        """POST a DescribeTable body carrying table_name_value for TableName, SigV4-signed."""
        data = json.dumps({"TableName": table_name_value}).encode()
        req = AWSRequest(method="POST", url=endpoint, data=data, headers={
            "content-type": "application/x-amz-json-1.0",
            "x-amz-target": "DynamoDB_20120810.DescribeTable"})
        SigV4Auth(frozen, "dynamodb", ctx.region).add_auth(req)
        sent = dict(req.headers.items())
        resp = pool.request("POST", endpoint, body=data, headers=sent, retries=False)
        body = json.loads(resp.data) if resp.data else {}
        return resp.status, body

    base = ctx.unique_name("sim2real-behav-ddbtntype-")
    absent = base + "-absent"
    table = base + "-t"

    ddb.create_table(
        TableName=table, BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _absent_ok(lambda: ddb.delete_table(TableName=table)))
    _await_table_active(ctx, ddb, table)

    # ---- 1. positive control: a string TableName naming a real table succeeds.
    status, body = raw(table)
    assert status == 200, f"a plain signed DescribeTable gave {status!r}: {body!r}"
    assert body.get("Table", {}).get("TableName") == table, (
        f"the describe answered about {body.get('Table', {}).get('TableName')!r}, not {table!r}")

    # ---- 2. baseline: a string TableName naming nothing gives the well-known lookup refusal --
    #         the baseline the type-mismatch refusals below must differ from.
    status, body_absent = raw(absent)
    assert status == 400, f"a plain signed DescribeTable on an absent table gave {status!r}"
    assert body_absent.get("__type", "").rsplit("#", 1)[-1] == _RNF, (
        f"an absent table gave __type {body_absent.get('__type')!r}, expected {_RNF!r}")

    # ---- 3. the refusal under test: TableName as each of several non-string JSON types gives
    #         SerializationException naming the JSON token it found, never the lookup refusal.
    matrix = [
        (42, "NUMBER_VALUE cannot be converted to String"),
        (3.14, "DECIMAL_VALUE cannot be converted to String"),
        (True, "TRUE_VALUE cannot be converted to String"),
        ({"a": 1}, "Start of structure or map found where not expected"),
    ]
    for value, expected_message in matrix:
        status, body = raw(value)
        assert status == 400, f"TableName={value!r} gave status {status!r}: {body!r}"
        err_type = body.get("__type", "").rsplit("#", 1)[-1]
        assert err_type == _SER, (
            f"TableName={value!r} gave __type {body.get('__type')!r}, expected {_SER!r}")
        assert body.get("Message") == expected_message, (
            f"TableName={value!r} gave message {body.get('Message')!r}, "
            f"expected {expected_message!r}")
        assert set(body) == {"__type", "Message"}, (
            f"TableName={value!r} refusal body carried extra members: {body!r}")

    # ---- 4. a JSON array also gives SerializationException, but with no Message at all --
    #         distinct enough from the scalar matrix above to be worth asserting on its own.
    status, body_array = raw(["a", "b"])
    assert status == 400, f"TableName=['a', 'b'] gave status {status!r}: {body_array!r}"
    assert body_array.get("__type", "").rsplit("#", 1)[-1] == _SER, (
        f"TableName=['a', 'b'] gave __type {body_array.get('__type')!r}, expected {_SER!r}")
    assert set(body_array) == {"__type"}, (
        f"TableName=['a', 'b'] refusal body carried a Message: {body_array!r}, "
        "expected only __type")

    # ---- 5. effect-absent: none of the refused calls created a table or disturbed the real one.
    names = []
    token = None
    while True:
        page = ddb.list_tables(**({"ExclusiveStartTableName": token} if token else {}))
        names.extend(n for n in page.get("TableNames", []) if n.startswith(base))
        token = page.get("LastEvaluatedTableName")
        if not token:
            break
    assert names == [table], (
        f"the refused calls left {sorted(set(names) - {table})!r} behind under {base!r}")
    assert ddb.describe_table(TableName=table)["Table"]["TableStatus"] == "ACTIVE", (
        "the real table is no longer ACTIVE after the refused calls")

    # ---- 6. verified teardown.
    ddb.delete_table(TableName=table)
    deadline = time.time() + _budget_s(ctx, 300.0)
    gone = None
    while time.time() < deadline:
        try:
            ddb.describe_table(TableName=table)
        except ClientError as exc:
            gone = exc.response.get("Error", {}).get("Code")
            break
        time.sleep(2.0)
    if gone is None and _budget_spent(ctx):
        raise TimeoutError(f"table {table!r} deleted: the run budget ended first; not graded")
    assert gone == _RNF, f"the table was still describable after delete_table (code {gone!r})"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
