"""sigv4-query-string-presigned-list-tables-tampered-signature-rejected."""
from __future__ import annotations

import json
import time
from urllib.parse import urlsplit, urlunsplit

import urllib3
from botocore.auth import SigV4QueryAuth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.utils import percent_encode_sequence

from behavioral_harness import tags

CHECK = "sigv4-query-string-presigned-list-tables-tampered-signature-rejected"
GROUP = "auth-signing-method"
SERVICES = ["dynamodb"]

#: Observed, named pair: DynamoDB's exact code and message for an invalid SigV4 signature.
_INVALID_SIGNATURE = (
    "InvalidSignatureException",
    "The request signature we calculated does not match the signature you provided. "
    "Check your AWS Secret Access Key and signing method. Consult the service documentation "
    "for details.",
)
_NAMESPACE = "com.amazon.coral.service"


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


def _presigned_url(endpoint, frozen, region, payload: dict) -> tuple[str, bytes, dict]:
    """A valid, query-string-signed ListTables request: its URL, body and headers."""
    creds = Credentials(frozen.access_key, frozen.secret_key, frozen.token)
    data = json.dumps(payload).encode()
    req = AWSRequest(method="POST", url=endpoint, data=data, headers={
        "content-type": "application/x-amz-json-1.0",
        "x-amz-target": "DynamoDB_20120810.ListTables"})
    _QueryStringAuth(creds, "dynamodb", region, expires=300).add_auth(req)
    return req.url, data, dict(req.headers.items())


def _presigned_page(verify, endpoint, frozen, region, payload: dict) -> dict:
    """One freshly-signed, query-string-authenticated ListTables page, over its own connection."""
    url, data, headers = _presigned_url(endpoint, frozen, region, payload)
    resp = _pool(verify).request("POST", url, body=data, headers=headers, retries=False)
    assert resp.status == 200, f"a query-string-signed ListTables page gave {resp.status!r}: {resp.data!r}"
    return json.loads(resp.data) if resp.data else {}


def _with_tampered_signature(url: str) -> str:
    """The same presigned URL with the trailing hex digits of ``X-Amz-Signature`` flipped."""
    assert url.endswith(("a", "b", "c", "d", "e", "f") + tuple("0123456789")), (
        f"presigned URL does not end in the signature's hex digits: {url!r}")
    return url[:-4] + ("0000" if url[-4:] != "0000" else "1111")


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


@tags("axis:rejection", "cap:unclassified", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A ListTables request presigned with SigV4 query-string parameters and no Authorization
    header is rejected with InvalidSignatureException when its X-Amz-Signature is altered; the
    same request with an unaltered signature succeeds.
    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-sigvqbad-")
    ddb.create_table(
        TableName=table, BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _await_table_active(ctx, ddb, table)

    endpoint = ddb.meta.endpoint_url
    frozen = _frozen_credentials(ddb)
    verify = ctx.http_verify

    # Each send below opens its own connection (a fresh pool per request): a connection that has
    # carried one rejected signature keeps rejecting every later request sent over it, correctly
    # signed or not, so reusing a connection across these assertions would make the positive
    # control fail for a reason that has nothing to do with the signature it carries.
    bad_url, bad_data, bad_headers = _presigned_url(endpoint, frozen, ctx.region, {})
    assert "authorization" not in {k.lower() for k in bad_headers}, (
        f"the presigned request still carried an Authorization header: {bad_headers!r}")
    tampered_url = _with_tampered_signature(bad_url)
    assert tampered_url != bad_url, "tampering produced the same URL; the probe asserts nothing"
    resp = _pool(verify).request("POST", tampered_url, body=bad_data, headers=bad_headers, retries=False)
    body = json.loads(resp.data) if resp.data else {}
    assert resp.status == 400, f"a tampered query-string signature gave {resp.status!r}: {body!r}"
    code, message = _INVALID_SIGNATURE
    assert body.get("__type") == f"{_NAMESPACE}#{code}", (
        f"a tampered signature gave __type {body.get('__type')!r}, expected "
        f"{_NAMESPACE + '#' + code!r}")
    assert body.get("message") == message, (
        f"a tampered signature's message was {body.get('message')!r}, expected {message!r}")

    # ---- positive control: an untampered presigned request, over its own connection, succeeds
    #      and lists the table this check created, so the rejection above is attributable to the
    #      tampered signature rather than to the endpoint or the account.
    good_url, good_data, good_headers = _presigned_url(endpoint, frozen, ctx.region, {})
    good_resp = _pool(verify).request("POST", good_url, body=good_data, headers=good_headers, retries=False)
    good_body = json.loads(good_resp.data) if good_resp.data else {}
    assert good_resp.status == 200, (
        f"the untampered presigned ListTables this probe tampered gave {good_resp.status!r}, "
        f"not 200: {good_body!r}")
    names = list(good_body.get("TableNames", []))
    token = good_body.get("LastEvaluatedTableName")
    while token:
        page = _presigned_page(verify, endpoint, frozen, ctx.region, {"ExclusiveStartTableName": token})
        names.extend(page.get("TableNames", []))
        token = page.get("LastEvaluatedTableName")
    assert table in names, (
        f"the positive control's presigned ListTables omits the table this check created: "
        f"{[n for n in names if table in n]!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
