"""incomplete-sigv4-signature-lists-missing-components."""
from __future__ import annotations

import base64
import hashlib
import json
import time
from email.utils import formatdate

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "incomplete-sigv4-signature-lists-missing-components"
GROUP = "request-authentication"
SERVICES = ["dynamodb"]

_INCOMPLETE_SIGNATURE = "com.amazon.coral.service#IncompleteSignatureException"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
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
        try:
            status = ddb.describe_table(TableName=table)["Table"]["TableStatus"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
        if status == "ACTIVE":
            return
        if time.time() >= deadline and _budget_spent(ctx):
            raise TimeoutError(f"table {table!r} ACTIVE: the run budget ended first; not graded")
        assert time.time() < deadline, f"table {table!r} never reached ACTIVE (last {status!r})"
        time.sleep(1.0)


def _absent_ok(fn) -> None:
    """Failure-path teardown for a resource the success path deletes itself: only an
    already-absent resource is tolerated, any other failure still surfaces."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _list_table_names(ddb) -> list[str]:
    """Every table name in this account and region, paginated."""
    names: list[str] = []
    for page in ddb.get_paginator("list_tables").paginate():
        names.extend(page.get("TableNames", []))
    return names


def _hashed_auth_trailer(auth_value: str) -> str:
    """The SHA-256/base64 digest DynamoDB echoes back for an unparseable Authorization value."""
    return base64.b64encode(hashlib.sha256(auth_value.encode()).digest()).decode()


def _send(pool, endpoint: str, *, headers: dict, body: bytes, query: str = ""):
    """POST raw bytes to the DynamoDB endpoint; return (status, parsed awsJson body)."""
    url = endpoint + (f"?{query}" if query else "")
    resp = pool.request("POST", url, body=body, headers=headers, retries=False)
    return resp.status, (json.loads(resp.data) if resp.data else {})


@tags("axis:rejection", "cap:unclassified", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An Authorization header with no SigV4 parameters, or with exactly one still missing, is
    refused with IncompleteSignatureException naming each missing component; an incomplete
    query-string signature is refused the same way, naming each missing query parameter.
    """
    import urllib3

    ddb = ctx.client("dynamodb")
    endpoint = ddb.meta.endpoint_url
    verify = ctx.http_verify
    pool = urllib3.PoolManager(cert_reqs="CERT_REQUIRED" if verify else "CERT_NONE",
                               ca_certs=verify if isinstance(verify, str) else None)

    base = ctx.unique_name("sim2real-behav-sigv4-")
    table = base + "-t"
    probe_table = base + "-create-probe"

    ddb.create_table(
        TableName=table, BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _absent_ok(lambda: ddb.delete_table(TableName=table)))
    _await_table_active(ctx, ddb, table)

    # ---- 1. a header-form Authorization with no SigV4 parameters at all and no X-Amz-Date or
    #         Date header either: every missing component is named, in order, and the trailer
    #         echoes the hashed literal value this check sent -- not a signature DynamoDB
    #         could not have computed, since nothing here was ever signed.
    ctx.on_cleanup(lambda: _absent_ok(lambda: ddb.delete_table(TableName=probe_table)))
    auth_bare = "AWS4-"
    create_body = json.dumps({
        "TableName": probe_table, "BillingMode": "PAY_PER_REQUEST",
        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
    }).encode()
    status, body = _send(pool, endpoint, body=create_body, headers={
        "content-type": "application/x-amz-json-1.0",
        "x-amz-target": "DynamoDB_20120810.CreateTable",
        "Authorization": auth_bare,
    })
    expected_bare = (
        "Authorization header requires 'Credential' parameter. "
        "Authorization header requires 'Signature' parameter. "
        "Authorization header requires 'SignedHeaders' parameter. "
        "Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header. "
        f"(Hashed with SHA-256 and encoded with Base64) Authorization={_hashed_auth_trailer(auth_bare)}")
    assert status == 400, f"a bare 'AWS4-' Authorization header gave status {status!r}: {body!r}"
    assert body.get("__type") == _INCOMPLETE_SIGNATURE, (
        f"a bare 'AWS4-' Authorization header gave __type {body.get('__type')!r}, expected "
        f"{_INCOMPLETE_SIGNATURE!r}")
    assert body.get("message") == expected_bare, (
        f"message was {body.get('message')!r}, expected {expected_bare!r}")

    # effect-absent: the refused CreateTable created nothing.
    names = _list_table_names(ddb)
    assert probe_table not in names, (
        f"a CreateTable refused for an incomplete signature created {probe_table!r} anyway")

    # ---- 2. a header-form Authorization missing only SignedHeaders, with a Date header
    #         present: only the one still-missing component is named.
    auth_partial = "AWS4- Signature=b, Credential=a"
    describe_body = json.dumps({"TableName": table}).encode()
    status, body = _send(pool, endpoint, body=describe_body, headers={
        "content-type": "application/x-amz-json-1.0",
        "x-amz-target": "DynamoDB_20120810.DescribeTable",
        "Authorization": auth_partial,
        "date": formatdate(usegmt=True),
    })
    expected_partial = (
        "Authorization header requires 'SignedHeaders' parameter. "
        f"(Hashed with SHA-256 and encoded with Base64) Authorization={_hashed_auth_trailer(auth_partial)}")
    assert status == 400, (
        f"an Authorization header missing only SignedHeaders gave status {status!r}: {body!r}")
    assert body.get("__type") == _INCOMPLETE_SIGNATURE, (
        f"an Authorization header missing only SignedHeaders gave __type {body.get('__type')!r}, "
        f"expected {_INCOMPLETE_SIGNATURE!r}")
    assert body.get("message") == expected_partial, (
        f"message was {body.get('message')!r}, expected {expected_partial!r}")

    # ---- 3. a query-string-form signature with an empty X-Amz-Algorithm and no other SigV4
    #         query parameter: every missing query-string parameter is named, ending in the
    #         re-examine sentence, and there is no Authorization header to name instead.
    status, body = _send(pool, endpoint, body=describe_body, query="X-Amz-Algorithm=", headers={
        "content-type": "application/x-amz-json-1.0",
        "x-amz-target": "DynamoDB_20120810.DescribeTable",
    })
    expected_query = (
        "AWS query-string parameters must include 'X-Amz-Algorithm'. "
        "AWS query-string parameters must include 'X-Amz-Credential'. "
        "AWS query-string parameters must include 'X-Amz-Signature'. "
        "AWS query-string parameters must include 'X-Amz-SignedHeaders'. "
        "AWS query-string parameters must include 'X-Amz-Date'. "
        "Re-examine the query-string parameters.")
    assert status == 400, f"an empty X-Amz-Algorithm query parameter gave status {status!r}: {body!r}"
    assert body.get("__type") == _INCOMPLETE_SIGNATURE, (
        f"an empty X-Amz-Algorithm query parameter gave __type {body.get('__type')!r}, expected "
        f"{_INCOMPLETE_SIGNATURE!r}")
    assert body.get("message") == expected_query, (
        f"message was {body.get('message')!r}, expected {expected_query!r}")

    # ---- 4. positive control: the same operation, properly signed through the SDK, still
    #         succeeds against the same table none of the refusals above touched.
    control = ddb.describe_table(TableName=table)["Table"]
    assert control["TableStatus"] == "ACTIVE", (
        f"a correctly signed DescribeTable did not see the table ACTIVE: {control!r}")

    names_after = _list_table_names(ddb)
    assert table in names_after, f"the control table is missing from ListTables: {names_after!r}"
    assert probe_table not in names_after, (
        f"the refused CreateTable's table appeared in ListTables by the end of the run")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
