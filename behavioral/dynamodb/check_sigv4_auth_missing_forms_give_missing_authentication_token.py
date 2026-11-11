"""sigv4-auth-missing-forms-give-missing-authentication-token."""
from __future__ import annotations

import binascii
import json
import time

import urllib3
from botocore.auth import SigV4QueryAuth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sigv4-auth-missing-forms-give-missing-authentication-token"
GROUP = "auth"
SERVICES = ["dynamodb"]

_ERR_TYPE = "com.amazon.coral.service#MissingAuthenticationTokenException"
_ERR_MESSAGE = "Request is missing Authentication Token"


def _budget_s(ctx, cap_s):
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _await_table_active(ctx, ddb, table: str) -> None:
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
        assert time.time() < deadline, f"table {table!r} never reached ACTIVE (last {status!r})"
        time.sleep(1.0)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A PutItem with no Authorization header, a truncated one, or SigV4 query parameters
    missing X-Amz-Algorithm is refused MissingAuthenticationTokenException and lands nothing.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table, KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST", Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _await_table_active(ctx, ddb, table)

    endpoint = ddb.meta.endpoint_url
    raw_creds = ddb._request_signer._credentials
    frozen = (raw_creds.get_frozen_credentials()
              if hasattr(raw_creds, "get_frozen_credentials") else raw_creds)
    verify = ctx.http_verify
    pool = urllib3.PoolManager(cert_reqs="CERT_REQUIRED" if verify else "CERT_NONE",
                               ca_certs=verify if isinstance(verify, str) else None)

    def _raw_put(pk: str, *, mode: str):
        """Send a hand-built PutItem; ``mode`` picks the auth shape under test."""
        body_dict = {"TableName": table, "Item": {"pk": {"S": pk}}}
        data = json.dumps(body_dict).encode()
        headers = {"content-type": "application/x-amz-json-1.0",
                   "x-amz-target": "DynamoDB_20120810.PutItem"}
        req = AWSRequest(method="POST", url=endpoint, data=data, headers=dict(headers))
        url = endpoint
        if mode == "signed":
            ddb._request_signer.sign("PutItem", req)
        elif mode == "no_auth_header":
            ddb._request_signer.sign("PutItem", req)
            del req.headers["Authorization"]
        elif mode == "truncated_auth_header":
            ddb._request_signer.sign("PutItem", req)
            req.headers["Authorization"] = "AWS4"
        elif mode == "query_auth_missing_algorithm":
            SigV4QueryAuth(frozen, "dynamodb", ctx.region, expires=3600).add_auth(req)
            prepared = req.prepare()
            from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
            parts = urlsplit(prepared.url)
            kept = [(k, v) for k, v in parse_qsl(parts.query) if k != "X-Amz-Algorithm"]
            url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(kept), parts.fragment))
            req = prepared
        else:
            raise AssertionError(f"unknown mode {mode!r}")
        sent_headers = dict(req.headers.items())
        resp = pool.request("POST", url, body=data, headers=sent_headers, retries=False)
        return (resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.data)

    def _landed(pk: str):
        return ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")

    # ---- positive control: a correctly signed raw PutItem over the same socket path lands.
    status, headers, raw_body = _raw_put("control-before", mode="signed")
    assert status == 200, f"a correctly signed raw PutItem gave {status!r}: {raw_body!r}"
    assert _landed("control-before") == {"pk": {"S": "control-before"}}, (
        "the correctly signed control PutItem did not land")

    for mode, pk in (
        ("no_auth_header", "no-auth-header"),
        ("truncated_auth_header", "truncated-auth-header"),
        ("query_auth_missing_algorithm", "query-auth-missing-algorithm"),
    ):
        status, headers, raw_body = _raw_put(pk, mode=mode)
        label = mode
        assert status == 400, f"{label}: expected status 400, got {status!r}: {raw_body!r}"
        parsed = json.loads(raw_body)
        assert parsed.get("__type") == _ERR_TYPE, (
            f"{label}: __type was {parsed.get('__type')!r}, expected {_ERR_TYPE!r}")
        assert parsed.get("message") == _ERR_MESSAGE, (
            f"{label}: message was {parsed.get('message')!r}, expected {_ERR_MESSAGE!r}")
        crc = headers.get("x-amz-crc32")
        assert crc, f"{label}: no x-amz-crc32 header on the error response: {headers!r}"
        assert int(crc) == (binascii.crc32(raw_body) & 0xFFFFFFFF), (
            f"{label}: x-amz-crc32 {crc!r} does not match the body's own checksum")
        assert _landed(pk) is None, f"{label}: a refused PutItem created {pk!r} anyway"

    # ---- positive control: the table and the raw channel are still healthy afterwards.
    status, headers, raw_body = _raw_put("control-after", mode="signed")
    assert status == 200, f"a correctly signed raw PutItem after the refusals gave {status!r}: {raw_body!r}"
    assert _landed("control-after") == {"pk": {"S": "control-after"}}, (
        "the trailing control PutItem did not land")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
