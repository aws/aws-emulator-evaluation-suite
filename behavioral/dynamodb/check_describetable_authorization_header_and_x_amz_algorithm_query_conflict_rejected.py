"""describetable-authorization-header-and-x-amz-algorithm-query-conflict-rejected."""
from __future__ import annotations

import json
import time

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describetable-authorization-header-and-x-amz-algorithm-query-conflict-rejected"
GROUP = "legacy-http-auth-conflict-rejected"
SERVICES = ["dynamodb"]

_RNF = "ResourceNotFoundException"
_ISE = "InvalidSignatureException"


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
    """A signed Authorization header together with an X-Amz-Algorithm query parameter is
    rejected with InvalidSignatureException and no message, before the table name is looked up.
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

    def raw(table_name: str, *, tamper_query: bool = False):
        """POST DescribeTable, signed with SigV4Auth; optionally add a literal
        X-Amz-Algorithm query parameter to the URL before signing."""
        url = endpoint + ("?X-Amz-Algorithm=AWS4-HMAC-SHA256" if tamper_query else "")
        data = json.dumps({"TableName": table_name}).encode()
        req = AWSRequest(method="POST", url=url, data=data, headers={
            "content-type": "application/x-amz-json-1.0",
            "x-amz-target": "DynamoDB_20120810.DescribeTable"})
        SigV4Auth(frozen, "dynamodb", ctx.region).add_auth(req)
        sent = dict(req.headers.items())
        assert "Authorization" in sent, f"SigV4Auth did not add an Authorization header: {sent!r}"
        resp = pool.request("POST", url, body=data, headers=sent, retries=False)
        body = json.loads(resp.data) if resp.data else {}
        return resp.status, {k.lower(): v for k, v in resp.headers.items()}, body

    base = ctx.unique_name("sim2real-behav-ddbauth-")
    absent = base + "-absent"
    table = base + "-t"

    ddb.create_table(
        TableName=table, BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _absent_ok(lambda: ddb.delete_table(TableName=table)))
    _await_table_active(ctx, ddb, table)

    # ---- 1. positive control: the raw signed request, untampered, against the real table.
    status, _headers, body = raw(table)
    assert status == 200, f"a plain signed DescribeTable gave {status!r}: {body!r}"
    assert body.get("Table", {}).get("TableName") == table, (
        f"the describe answered about {body.get('Table', {}).get('TableName')!r}, not {table!r}")
    assert body["Table"]["TableStatus"] == "ACTIVE", (
        f"the real table read back as {body['Table']['TableStatus']!r}, not ACTIVE")

    # ---- 2. control: the same raw signing path against an absent table gives a distinct,
    #         well-known refusal -- the baseline this check's refusal must differ from.
    status, _headers, body_absent = raw(absent)
    assert status == 400, f"a plain signed DescribeTable on an absent table gave {status!r}"
    assert body_absent.get("__type", "").rsplit("#", 1)[-1] == _RNF, (
        f"an absent table gave __type {body_absent.get('__type')!r}, expected {_RNF!r}")

    # ---- 3. the refusal under test: the same request, plus a literal X-Amz-Algorithm query
    #         parameter alongside the Authorization header SigV4Auth still adds.
    status, _headers, body_tampered = raw(absent, tamper_query=True)
    assert status == 400, (
        f"a request carrying both Authorization and X-Amz-Algorithm gave {status!r}: "
        f"{body_tampered!r}")
    err_type = body_tampered.get("__type", "").rsplit("#", 1)[-1]
    assert err_type == _ISE, (
        f"a request carrying both Authorization and X-Amz-Algorithm gave __type "
        f"{body_tampered.get('__type')!r}, expected {_ISE!r}")
    assert "message" not in body_tampered, (
        f"a request carrying both Authorization and X-Amz-Algorithm carried a message "
        f"{body_tampered.get('message')!r} -- measured, DynamoDB sends none for this refusal")
    assert body_tampered == {"__type": f"com.amazon.coral.service#{_ISE}"}, (
        f"the refusal body was {body_tampered!r}, expected only __type with no other member")
    assert err_type != body_absent.get("__type", "").rsplit("#", 1)[-1], (
        "the header/query conflict collapsed into the same code as a plain missing-table refusal")

    # ---- 4. the conflict is checked before the table lookup: the SAME refusal appears for a
    #         table that exists, proving it does not depend on -- or wait for -- resolving the name.
    status, _headers, body_tampered_existing = raw(table, tamper_query=True)
    assert status == 400, (
        f"the same conflict against an existing table gave {status!r}: "
        f"{body_tampered_existing!r}")
    err_type_existing = body_tampered_existing.get("__type", "").rsplit("#", 1)[-1]
    assert err_type_existing == _ISE, (
        f"the conflict against an existing table gave __type "
        f"{body_tampered_existing.get('__type')!r}, expected {_ISE!r}")
    assert body_tampered_existing == body_tampered, (
        f"the conflict's body changed with the table name: {body_tampered_existing!r} vs "
        f"{body_tampered!r}")

    # ---- 5. effect-absent: none of the refused calls created anything, and the real table is
    #         unaffected by them.
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
