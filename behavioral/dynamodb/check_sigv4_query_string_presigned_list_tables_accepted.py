"""sigv4-query-string-presigned-list-tables-accepted."""
from __future__ import annotations

import binascii
import json
import time
from urllib.parse import urlsplit, urlunsplit

import urllib3
from botocore.auth import SigV4QueryAuth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.utils import percent_encode_sequence

from behavioral_harness import tags

CHECK = "sigv4-query-string-presigned-list-tables-accepted"
GROUP = "auth-signing-method"
SERVICES = ["dynamodb"]


class _QueryStringAuth(SigV4QueryAuth):
    """SigV4 query-string (presigned) auth that keeps the request body in place.

    The inherited ``SigV4QueryAuth`` moves the body into the query string, which assumes a
    form-urlencoded query-protocol body; it does not apply to an awsJson request, whose body is
    JSON. This override only moves the auth parameters into the query string and leaves the JSON
    body (and its hash, which the inherited ``payload()`` still signs) untouched.
    """

    def _modify_request_before_signing(self, request):
        signed_headers = self.signed_headers(self.headers_to_sign(request))
        auth_params = {
            "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
            "X-Amz-Credential": self.scope(request),
            "X-Amz-Date": request.context["timestamp"],
            "X-Amz-Expires": self._expires,
            "X-Amz-SignedHeaders": signed_headers,
        }
        if self.credentials.token is not None:
            auth_params["X-Amz-Security-Token"] = self.credentials.token
        parts = urlsplit(request.url)
        new_query = (parts.query + "&" if parts.query else "") + percent_encode_sequence(auth_params)
        request.url = urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


def _frozen_credentials(client):
    """The frozen botocore credentials backing ``client``'s own request signer."""
    raw = client._request_signer._credentials
    return raw.get_frozen_credentials() if hasattr(raw, "get_frozen_credentials") else raw


def _pool(verify):
    """A urllib3 pool honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    return urllib3.PoolManager(cert_reqs="CERT_REQUIRED" if verify else "CERT_NONE",
                               ca_certs=verify if isinstance(verify, str) else None)


def _presigned_list_tables(pool, endpoint, frozen, region, payload: dict):
    """Build and send one ListTables request authenticated with query-string parameters only.

    Returns ``(status, headers, body_dict, sent_headers, raw_body)``. ``sent_headers`` lets the
    caller confirm no ``Authorization`` header carries any part of the signature.
    """
    creds = Credentials(frozen.access_key, frozen.secret_key, frozen.token)
    data = json.dumps(payload).encode()
    req = AWSRequest(method="POST", url=endpoint, data=data, headers={
        "content-type": "application/x-amz-json-1.0",
        "x-amz-target": "DynamoDB_20120810.ListTables"})
    _QueryStringAuth(creds, "dynamodb", region, expires=300).add_auth(req)
    sent_headers = dict(req.headers.items())
    resp = pool.request("POST", req.url, body=data, headers=sent_headers, retries=False)
    body = json.loads(resp.data) if resp.data else {}
    return resp.status, {k.lower(): v for k, v in resp.headers.items()}, body, sent_headers, resp.data


def _await_table_active(ctx, ddb, table: str) -> None:
    """Poll DescribeTable until the table is ACTIVE, bounded by the run's own budget."""
    left = ctx.time_left()
    deadline = time.time() + (300.0 if left is None else max(1.0, min(300.0, left - 5.0)))
    status = None
    while time.time() < deadline:
        status = ddb.describe_table(TableName=table)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return
        time.sleep(1.0)
    raise AssertionError(f"table {table!r} never reached ACTIVE (last {status!r})")


@tags("axis:happy-path", "cap:unclassified", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A ListTables request signed with SigV4 query-string parameters, carrying no Authorization
    header, is accepted and returns the real inventory, including a table created in this run.
    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-sigvq-")

    ddb.create_table(
        TableName=table, BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _await_table_active(ctx, ddb, table)

    endpoint = ddb.meta.endpoint_url
    frozen = _frozen_credentials(ddb)
    pool = _pool(ctx.http_verify)

    status, headers, body, sent_headers, raw = _presigned_list_tables(pool, endpoint, frozen, ctx.region, {})
    assert "authorization" not in {k.lower() for k in sent_headers}, (
        f"the presigned request still carried an Authorization header: {sent_headers!r}")
    assert status == 200, f"a query-string-signed ListTables gave {status!r}, not 200: {body!r}"
    crc = headers.get("x-amz-crc32")
    assert crc == str(binascii.crc32(raw) & 0xFFFFFFFF), (
        f"x-amz-crc32 {crc!r} is not the CRC32 of the 200 response body: {headers!r}")
    names = list(body.get("TableNames", []))
    token = body.get("LastEvaluatedTableName")
    while token:
        status, _headers, page, _sent, _raw = _presigned_list_tables(
            pool, endpoint, frozen, ctx.region, {"ExclusiveStartTableName": token})
        assert status == 200, f"a paged query-string-signed ListTables gave {status!r}: {page!r}"
        names.extend(page.get("TableNames", []))
        token = page.get("LastEvaluatedTableName")

    assert table in names, (
        f"the presigned ListTables inventory omits the table this run created: "
        f"{[n for n in names if table in n]!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
