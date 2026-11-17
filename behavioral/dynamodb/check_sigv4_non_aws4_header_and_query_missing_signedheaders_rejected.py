"""sigv4-non-aws4-header-and-query-missing-signedheaders-rejected."""
from __future__ import annotations

import binascii
import json
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from botocore.auth import SigV4QueryAuth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sigv4-non-aws4-header-and-query-missing-signedheaders-rejected"
GROUP = "request-authentication"
SERVICES = ["dynamodb"]

_MISSING_TOKEN = ("com.amazon.coral.service#MissingAuthenticationTokenException",
                   "Request is missing Authentication Token")
_INCOMPLETE_SIGNED_HEADERS = (
    "com.amazon.coral.service#IncompleteSignatureException",
    "AWS query-string parameters must include 'X-Amz-SignedHeaders'. "
    "Re-examine the query-string parameters.")


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


def expect_error(status: int, body: dict, raw_body: bytes, headers: dict, _X) -> None:
    code, message = _X
    assert status == 400, f"expected status 400, got {status!r}: {body!r}"
    assert body.get("__type") == code, (
        f"__type was {body.get('__type')!r}, expected {code!r}: {body!r}")
    assert body.get("message") == message, (
        f"message was {body.get('message')!r}, expected {message!r}")
    crc = headers.get("x-amz-crc32")
    assert crc, f"no x-amz-crc32 header on the error response: {headers!r}"
    assert int(crc) == (binascii.crc32(raw_body) & 0xFFFFFFFF), (
        f"x-amz-crc32 {crc!r} does not match the body's own checksum")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A non-'AWS4-' Authorization header is refused MissingAuthenticationToken; a complete
    query-string SigV4 signature missing only X-Amz-SignedHeaders is refused
    IncompleteSignatureException naming that one parameter. Neither lands an item."""
    import urllib3

    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-sigv4np-")
    ddb.create_table(
        TableName=table, BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _absent_ok(lambda: ddb.delete_table(TableName=table)))
    _await_table_active(ctx, ddb, table)

    endpoint = ddb.meta.endpoint_url
    raw_creds = ddb._request_signer._credentials
    frozen = (raw_creds.get_frozen_credentials()
              if hasattr(raw_creds, "get_frozen_credentials") else raw_creds)
    verify = ctx.http_verify
    pool = urllib3.PoolManager(cert_reqs="CERT_REQUIRED" if verify else "CERT_NONE",
                               ca_certs=verify if isinstance(verify, str) else None)

    def _landed(pk: str):
        return ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")

    def _raw_put(pk: str):
        """A raw signed PutItem over the same socket path; returns (status, headers, raw body)."""
        data = json.dumps({"TableName": table, "Item": {"pk": {"S": pk}}}).encode()
        req = AWSRequest(method="POST", url=endpoint, data=data, headers={
            "content-type": "application/x-amz-json-1.0",
            "x-amz-target": "DynamoDB_20120810.PutItem"})
        from botocore.auth import SigV4Auth
        SigV4Auth(frozen, "dynamodb", ctx.region).add_auth(req)
        sent = dict(req.headers.items())
        resp = pool.request("POST", endpoint, body=data, headers=sent, retries=False)
        return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.data

    # ---- positive control: a correctly signed raw PutItem lands.
    status, headers, raw_body = _raw_put("control-before")
    assert status == 200, f"a correctly signed raw PutItem gave {status!r}: {raw_body!r}"
    assert _landed("control-before") == {"pk": {"S": "control-before"}}, (
        "the correctly signed control PutItem did not land")

    # ---- 1. an Authorization header that does not start with 'AWS4-' at all, with no
    #         SigV4 query parameters either: DynamoDB treats it as no authentication attempt.
    pk1 = "non-aws4-header"
    data1 = json.dumps({"TableName": table, "Item": {"pk": {"S": pk1}}}).encode()
    resp1 = pool.request("POST", endpoint, body=data1, headers={
        "content-type": "application/x-amz-json-1.0",
        "x-amz-target": "DynamoDB_20120810.PutItem",
        "Authorization": "X",
    }, retries=False)
    headers1 = {k.lower(): v for k, v in resp1.headers.items()}
    body1 = json.loads(resp1.data) if resp1.data else {}
    expect_error(resp1.status, body1, resp1.data, headers1, _MISSING_TOKEN)
    assert _landed(pk1) is None, f"a non-AWS4 Authorization header PutItem created {pk1!r} anyway"

    # ---- 2. a query-string SigV4 signature with every parameter present except
    #         X-Amz-SignedHeaders: only that one parameter is named missing, not the full list.
    pk2 = "query-missing-signedheaders"
    data2 = json.dumps({"TableName": table, "Item": {"pk": {"S": pk2}}}).encode()
    req2 = AWSRequest(method="POST", url=endpoint, data=data2, headers={
        "content-type": "application/x-amz-json-1.0",
        "x-amz-target": "DynamoDB_20120810.PutItem"})
    SigV4QueryAuth(frozen, "dynamodb", ctx.region, expires=3600).add_auth(req2)
    prepared2 = req2.prepare()
    parts2 = urlsplit(prepared2.url)
    all_params2 = parse_qsl(parts2.query)
    assert "X-Amz-SignedHeaders" in {k for k, _ in all_params2}, (
        f"the complete query-string signature never carried X-Amz-SignedHeaders to remove: "
        f"{all_params2!r}")
    kept2 = [(k, v) for k, v in all_params2 if k != "X-Amz-SignedHeaders"]
    assert {k for k, _ in kept2} == {
        "TableName", "Item", "X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Date",
        "X-Amz-Expires", "X-Amz-Signature"}, (
        f"unexpected query parameters after removing only X-Amz-SignedHeaders: {kept2!r}")
    url2 = urlunsplit((parts2.scheme, parts2.netloc, parts2.path, urlencode(kept2), parts2.fragment))
    headers2_sent = dict(prepared2.headers.items())
    resp2 = pool.request("POST", url2, body=data2, headers=headers2_sent, retries=False)
    headers2 = {k.lower(): v for k, v in resp2.headers.items()}
    body2 = json.loads(resp2.data) if resp2.data else {}
    expect_error(resp2.status, body2, resp2.data, headers2, _INCOMPLETE_SIGNED_HEADERS)
    assert _landed(pk2) is None, (
        f"a query-string signature missing only X-Amz-SignedHeaders created {pk2!r} anyway")

    # ---- positive control: the table and the raw channel are still healthy afterwards.
    status, headers, raw_body = _raw_put("control-after")
    assert status == 200, f"a correctly signed raw PutItem after the refusals gave {status!r}: {raw_body!r}"
    assert _landed("control-after") == {"pk": {"S": "control-after"}}, (
        "the trailing control PutItem did not land")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
