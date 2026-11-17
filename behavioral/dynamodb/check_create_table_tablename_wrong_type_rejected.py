"""create-table-tablename-wrong-type-rejected."""
from __future__ import annotations

import json
import time

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-table-tablename-wrong-type-rejected"
GROUP = "create-table-member-type-mismatches"
SERVICES = ["dynamodb"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation",
      "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """CreateTable refuses a TableName sent as a JSON number with a serializer error, while
    a correctly typed TableName over the same signed route still creates, reads back and deletes.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_CreateTable.html
    """
    import urllib3

    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ctname-")

    raw_creds = ddb._request_signer._credentials
    frozen = (raw_creds.get_frozen_credentials()
              if hasattr(raw_creds, "get_frozen_credentials") else raw_creds)
    endpoint = ddb.meta.endpoint_url
    verify = ctx.http_verify
    pool = urllib3.PoolManager(cert_reqs="CERT_REQUIRED" if verify else "CERT_NONE",
                               ca_certs=verify if isinstance(verify, str) else None)

    def raw(body: dict):
        data = json.dumps(body).encode()
        req = AWSRequest(method="POST", url=endpoint, data=data, headers={
            "content-type": "application/x-amz-json-1.0",
            "x-amz-target": "DynamoDB_20120810.CreateTable"})
        SigV4Auth(frozen, "dynamodb", ctx.region).add_auth(req)
        sent = dict(req.headers.items())
        resp = pool.request("POST", endpoint, body=data, headers=sent, retries=False)
        return resp.status, (json.loads(resp.data) if resp.data else {})

    # ---- the malformed call: TableName sent as a JSON number, not a string.
    status, body = raw({
        "TableName": 1234567890,
        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
        "BillingMode": "PAY_PER_REQUEST",
    })
    assert status == 400, f"CreateTable with a numeric TableName gave status {status!r}: {body!r}"
    assert body.get("__type") == "com.amazon.coral.service#SerializationException", (
        f"CreateTable with a numeric TableName gave __type {body.get('__type')!r}, expected "
        "'com.amazon.coral.service#SerializationException'")
    assert body.get("Message") == "NUMBER_VALUE cannot be converted to String", (
        f"CreateTable with a numeric TableName gave message {body.get('Message')!r}, expected "
        "'NUMBER_VALUE cannot be converted to String'")

    # ---- positive control, over the same signed route: a correctly typed TableName still works.
    status, body = raw({
        "TableName": table,
        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
        "BillingMode": "PAY_PER_REQUEST",
    })
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table),
                             "ResourceNotFoundException"))
    assert status == 200, f"CreateTable with a string TableName gave status {status!r}: {body!r}"
    assert body["TableDescription"]["TableName"] == table, (
        f"CreateTable echoed TableName {body['TableDescription']['TableName']!r}, expected "
        f"{table!r}")

    deadline = time.time() + 300.0
    status_now = None
    while time.time() < deadline:
        status_now = ddb.describe_table(TableName=table)["Table"]["TableStatus"]
        if status_now == "ACTIVE":
            break
        time.sleep(2.0)
    assert status_now == "ACTIVE", f"table {table!r} never reached ACTIVE (last {status_now!r})"
    desc = ddb.describe_table(TableName=table)["Table"]
    assert desc["TableName"] == table, f"describe named {desc['TableName']!r}, expected {table!r}"

    ddb.delete_table(TableName=table)
    deadline = time.time() + 300.0
    gone = None
    while time.time() < deadline:
        try:
            ddb.describe_table(TableName=table)
        except ClientError as exc:
            gone = exc.response["Error"]["Code"]
            break
        time.sleep(2.0)
    assert gone == "ResourceNotFoundException", (
        f"table {table!r} still describable after delete_table (code {gone!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
