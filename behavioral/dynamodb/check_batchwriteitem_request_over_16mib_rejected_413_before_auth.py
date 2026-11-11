"""batchwriteitem-request-over-16mib-rejected-413-before-auth."""
from __future__ import annotations

import json

import urllib3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

from behavioral_harness import tags

CHECK = "batchwriteitem-request-over-16mib-rejected-413-before-auth"
GROUP = "http-body-size-limits"
SERVICES = ["dynamodb"]

_LIMIT_BYTES = 16 * 1024 * 1024  # 16777216
_TARGET = "DynamoDB_20120810.BatchWriteItem"
_MISSING_AUTH = (
    "com.amazon.coral.service#MissingAuthenticationTokenException",
    "Request is missing Authentication Token",
)
_REQUEST_ITEMS_REQUIRED = (
    "com.amazon.coral.validate#ValidationException",
    "The requestItems parameter is required for BatchWriteItem",
)


def _sized_empty_batch_body(total_bytes: int) -> bytes:
    """A syntactically valid JSON body carrying an empty RequestItems map plus a filler
    attribute, sized to EXACTLY total_bytes so any downstream rejection is about
    RequestItems, never about the padding."""
    pad_len = total_bytes
    while True:
        encoded = json.dumps({"RequestItems": {}, "pad": "a" * pad_len}).encode()
        if len(encoded) == total_bytes:
            return encoded
        pad_len += total_bytes - len(encoded)


def _post(pool, endpoint, region, creds, body: bytes, *, signed: bool):
    """POST body as a BatchWriteItem call, signed or left with no Authorization header at
    all; returns (status, reason phrase, lowercased headers, raw body bytes)."""
    headers = {"content-type": "application/x-amz-json-1.0", "x-amz-target": _TARGET}
    if signed:
        req = AWSRequest(method="POST", url=endpoint, data=body, headers=headers)
        SigV4Auth(creds, "dynamodb", region).add_auth(req)
        headers = dict(req.headers.items())
    resp = pool.request("POST", endpoint, body=body, headers=headers, retries=False, timeout=90.0)
    return (resp.status, getattr(resp, "reason", None),
            {k.lower(): v for k, v in resp.headers.items()}, resp.data)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation",
      "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An unsigned raw BatchWriteItem request one byte over 16 MiB is refused with an empty-bodied
    HTTP 413 before authentication, while the same request at a small size is refused for its
    missing authentication token, and signed is judged on its empty RequestItems.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # ---- positive control: a normal, authenticated BatchWriteItem writes and reads back,
    #      so the raw-body legs below are compared against a table that is known to work.
    control_key = ctx.unique_name("sim2real-item-")
    ddb.batch_write_item(RequestItems={table: [{"PutRequest": {"Item": {"pk": {"S": control_key}}}}]})
    control_item = ddb.get_item(TableName=table, Key={"pk": {"S": control_key}}, ConsistentRead=True)
    assert control_item.get("Item") == {"pk": {"S": control_key}}, (
        f"the control write did not read back: {control_item.get('Item')!r}"
    )

    endpoint = ddb.meta.endpoint_url
    raw_creds = ddb._request_signer._credentials
    frozen = (raw_creds.get_frozen_credentials()
              if hasattr(raw_creds, "get_frozen_credentials") else raw_creds)
    verify = ctx.http_verify
    pool = urllib3.PoolManager(cert_reqs="CERT_REQUIRED" if verify else "CERT_NONE",
                               ca_certs=verify if isinstance(verify, str) else None)

    small = _sized_empty_batch_body(1024)
    over_limit = _sized_empty_batch_body(_LIMIT_BYTES + 1)

    # ---- positive controls at a small size: the size gate lets the body through, so the
    #      unsigned request is judged on authentication and the signed one on validation.
    status, _reason, _headers, body = _post(pool, endpoint, ctx.region, frozen, small, signed=False)
    assert status == 400, f"a small unsigned body gave {status!r}, not 400: {body!r}"
    parsed = json.loads(body)
    assert (parsed.get("__type"), parsed.get("message")) == _MISSING_AUTH, (
        f"a small unsigned body gave {parsed!r}, expected __type/message {_MISSING_AUTH!r}"
    )

    status, _reason, _headers, body = _post(pool, endpoint, ctx.region, frozen, small, signed=True)
    assert status == 400, f"a small signed body gave {status!r}, not 400: {body!r}"
    parsed = json.loads(body)
    assert (parsed.get("__type"), parsed.get("message")) == _REQUEST_ITEMS_REQUIRED, (
        f"a small signed body gave {parsed!r}, expected __type/message {_REQUEST_ITEMS_REQUIRED!r}"
    )

    # ---- one byte over 16 MiB, unsigned: refused with 413 instead of the missing-token 400
    #      above, so the size gate runs before authentication.
    status, reason, headers, body = _post(pool, endpoint, ctx.region, frozen, over_limit, signed=False)
    assert status == 413, f"a 16MiB+1-byte unsigned body gave {status!r}, not 413: {body!r}"
    assert reason == "Request Entity Too Large", (
        f"the 413's reason phrase was {reason!r}, not 'Request Entity Too Large'"
    )
    assert body == b"", f"the 413 response carried a body: {body!r}"
    assert headers.get("content-length") == "0", (
        f"the 413 response Content-Length was {headers.get('content-length')!r}, not '0'"
    )
    assert headers.get("connection") == "close", (
        f"the 413 response Connection header was {headers.get('connection')!r}, not 'close'"
    )
    assert "content-type" not in headers, (
        f"the 413 response unexpectedly carried a Content-Type: {headers.get('content-type')!r}"
    )

    # ---- effect-absent: every raw body above carried an empty RequestItems map, so the
    #      table still holds only the control item -- none of the three requests wrote anything.
    scan = ddb.scan(TableName=table, ConsistentRead=True)
    assert scan["Items"] == [{"pk": {"S": control_key}}], (
        f"the table holds more than the control item after the raw requests: {scan['Items']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
