"""deletetable-tablename-wrong-json-type-serialization-exception."""
from __future__ import annotations

import json
import time

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deletetable-tablename-wrong-json-type-serialization-exception"
GROUP = "legacy-http-auth-conflict-rejected"
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
    """Failure-path teardown for a resource the success path already deletes."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """DeleteTable with TableName sent as a non-string JSON value is rejected with
    SerializationException, naming the offending token, regardless of which tables exist.
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

    def raw(table_name):
        """POST DeleteTable, signed with SigV4Auth, with the given raw JSON value as TableName."""
        data = json.dumps({"TableName": table_name}).encode()
        req = AWSRequest(method="POST", url=endpoint, data=data, headers={
            "content-type": "application/x-amz-json-1.0",
            "x-amz-target": "DynamoDB_20120810.DeleteTable"})
        SigV4Auth(frozen, "dynamodb", ctx.region).add_auth(req)
        sent = dict(req.headers.items())
        assert "Authorization" in sent, f"SigV4Auth did not add an Authorization header: {sent!r}"
        resp = pool.request("POST", endpoint, body=data, headers=sent, retries=False)
        body = json.loads(resp.data) if resp.data else {}
        return resp.status, body

    base = ctx.unique_name("sim2real-behav-ddbdel-")
    absent = base + "-absent"
    table = base + "-t"

    ddb.create_table(
        TableName=table, BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _absent_ok(lambda: ddb.delete_table(TableName=table)))
    _await_table_active(ctx, ddb, table)

    # ---- 1. control: a correctly typed TableName against an absent table gives the
    #         well-known resource-not-found refusal -- the baseline the type error must differ from.
    status, body_absent = raw(absent)
    assert status == 400, f"a correctly typed DeleteTable on an absent table gave {status!r}"
    assert body_absent.get("__type", "").rsplit("#", 1)[-1] == _RNF, (
        f"a correctly typed DeleteTable on an absent table gave __type "
        f"{body_absent.get('__type')!r}, expected {_RNF!r}")

    # ---- 2. the refusal under test: a JSON number where TableName (a string) is expected.
    status, body_number = raw(12345)
    assert status == 400, f"TableName as a JSON number gave {status!r}: {body_number!r}"
    err_type_number = body_number.get("__type", "").rsplit("#", 1)[-1]
    assert err_type_number == _SER, (
        f"TableName as a JSON number gave __type {body_number.get('__type')!r}, expected "
        f"{_SER!r}")
    assert body_number.get("Message") == "NUMBER_VALUE cannot be converted to String", (
        f"TableName as a JSON number gave message {body_number.get('Message')!r}, expected "
        "'NUMBER_VALUE cannot be converted to String'")
    assert err_type_number != body_absent.get("__type", "").rsplit("#", 1)[-1], (
        "the type error collapsed into the same code as the missing-table refusal")

    # ---- 3. a second non-string JSON type on the same member: a list, which carries no message.
    status, body_list = raw(["x"])
    assert status == 400, f"TableName as a JSON list gave {status!r}: {body_list!r}"
    assert body_list.get("__type", "").rsplit("#", 1)[-1] == _SER, (
        f"TableName as a JSON list gave __type {body_list.get('__type')!r}, expected {_SER!r}")
    assert "Message" not in body_list, (
        f"TableName as a JSON list carried a message {body_list.get('Message')!r} -- measured, "
        "DynamoDB sends none for this refusal")
    assert body_list == {"__type": body_number["__type"].rsplit("#", 1)[0] + "#" + _SER}, (
        f"the list refusal body was {body_list!r}, expected only __type with no other member")

    # ---- 4. effect-absent: none of the refused calls deleted or created anything. Both type
    #         refusals above already ran while this real table coexisted in the account, so the
    #         type check is shown not to depend on which names would otherwise be looked up.
    assert ddb.describe_table(TableName=table)["Table"]["TableStatus"] == "ACTIVE", (
        "the real table is no longer ACTIVE after the refused calls")
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

    # ---- 5. positive control: the same raw signed path, with TableName correctly typed as a
    #         string, actually deletes the real table.
    status, body_deleted = raw(table)
    assert status == 200, f"a correctly typed DeleteTable against the real table gave {status!r}: {body_deleted!r}"
    assert body_deleted.get("TableDescription", {}).get("TableName") == table, (
        f"the delete answered about {body_deleted.get('TableDescription', {}).get('TableName')!r}, "
        f"not {table!r}")

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
