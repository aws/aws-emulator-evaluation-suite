"""batchwriteitem-requestitems-wrong-json-type-rejected."""
from __future__ import annotations

import json
import time

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batchwriteitem-requestitems-wrong-json-type-rejected"
GROUP = "batch"
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


def _absent_ok(fn) -> None:
    """Failure-path teardown for a resource the success path already deleted."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """BatchWriteItem refuses a RequestItems that is a JSON string or number with
    SerializationException "Unexpected field type", and a JSON array with a SerializationException
    carrying no Message; none of them writes an item."""
    import urllib3

    ddb = ctx.client("dynamodb")
    endpoint = ddb.meta.endpoint_url
    raw_creds = ddb._request_signer._credentials
    frozen = (raw_creds.get_frozen_credentials()
              if hasattr(raw_creds, "get_frozen_credentials") else raw_creds)
    verify = ctx.http_verify
    pool = urllib3.PoolManager(cert_reqs="CERT_REQUIRED" if verify else "CERT_NONE",
                               ca_certs=verify if isinstance(verify, str) else None)

    def raw(request_items_value):
        """POST a BatchWriteItem body carrying request_items_value for RequestItems, SigV4-signed."""
        data = json.dumps({"RequestItems": request_items_value}).encode()
        req = AWSRequest(method="POST", url=endpoint, data=data, headers={
            "content-type": "application/x-amz-json-1.0",
            "x-amz-target": "DynamoDB_20120810.BatchWriteItem"})
        SigV4Auth(frozen, "dynamodb", ctx.region).add_auth(req)
        sent = dict(req.headers.items())
        resp = pool.request("POST", endpoint, body=data, headers=sent, retries=False)
        body = json.loads(resp.data) if resp.data else {}
        return resp.status, body

    base = ctx.unique_name("sim2real-behav-ddbbwitype-")
    table = base + "-t"

    ddb.create_table(
        TableName=table, BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _absent_ok(lambda: ddb.delete_table(TableName=table)))
    _await_table_active(ctx, ddb, table)

    # ---- 1. positive control: a well-formed RequestItems map against the real table succeeds.
    status, body = raw({table: [{"PutRequest": {"Item": {"pk": {"S": "control"}}}}]})
    assert status == 200, f"a plain signed BatchWriteItem gave {status!r}: {body!r}"
    assert body == {"UnprocessedItems": {}}, f"unexpected success body: {body!r}"
    got = ddb.scan(TableName=table, ConsistentRead=True)
    assert got["Items"] == [{"pk": {"S": "control"}}], f"positive control not visible: {got}"

    # ---- 2. the refusal under test: RequestItems as a JSON string or number gives
    #         SerializationException with the same "Unexpected field type" message.
    matrix = [
        ("a string", "oops", "Unexpected field type"),
        ("a number", 42, "Unexpected field type"),
    ]
    for label, value, expected_message in matrix:
        status, body = raw(value)
        assert status == 400, f"RequestItems={value!r} ({label}) gave status {status!r}: {body!r}"
        err_type = body.get("__type", "").rsplit("#", 1)[-1]
        assert err_type == _SER, (
            f"RequestItems={value!r} ({label}) gave __type {body.get('__type')!r}, "
            f"expected {_SER!r}")
        assert body.get("Message") == expected_message, (
            f"RequestItems={value!r} ({label}) gave message {body.get('Message')!r}, "
            f"expected {expected_message!r}")
        assert set(body) == {"__type", "Message"}, (
            f"RequestItems={value!r} ({label}) refusal body carried extra members: {body!r}")

    # ---- 3. a JSON array also gives SerializationException, kept separate from the scalar
    #         matrix above since the array's refusal body carries no Message at all.
    status, body_array = raw(["a", "b"])
    assert status == 400, f"RequestItems=['a', 'b'] gave status {status!r}: {body_array!r}"
    assert body_array.get("__type", "").rsplit("#", 1)[-1] == _SER, (
        f"RequestItems=['a', 'b'] gave __type {body_array.get('__type')!r}, expected {_SER!r}")
    assert set(body_array) == {"__type"}, (
        f"RequestItems=['a', 'b'] refusal body carried a Message: {body_array!r}, "
        "expected only __type")

    # ---- 4. effect-absent: none of the refused calls wrote anything to the real table.
    after = ddb.scan(TableName=table, ConsistentRead=True)
    assert after["Items"] == [{"pk": {"S": "control"}}], (
        f"the refused calls disturbed the table, got {after['Items']!r}")

    # ---- 5. verified teardown.
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
