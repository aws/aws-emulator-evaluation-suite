"""get-resources-rpc-v2-cbor-request-accepted."""
from __future__ import annotations

import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "get-resources-rpc-v2-cbor-request-accepted"
GROUP = "protocol"
SERVICES = ["resourcegroupstaggingapi", "sqs"]

_PATH = "/service/ResourceGroupsTaggingAPI_20170126/operation/GetResources"
_HEADERS = {
    "smithy-protocol": "rpc-v2-cbor",
    "Content-Type": "application/cbor",
    "Accept": "application/cbor",
}


@tags("axis:happy-path", "cap:c2", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A GetResources tag query framed as a Smithy RPC v2 CBOR request, with no X-Amz-Target
    header, is served by the tagging endpoint and returns the same tag mapping a plain
    JSON-protocol query returns, before and after the CBOR request is sent."""
    sqs = ctx.client("sqs")
    rgta = ctx.client("resourcegroupstaggingapi")
    queue_name = ctx.unique_name("sim2real-behav-rgta-")
    queue_url = sqs.create_queue(QueueName=queue_name)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    tag_key = ctx.unique_name("sim2real-behav-rgta-key-")
    tag_value = ctx.unique_name("sim2real-behav-rgta-val-")
    failed = rgta.tag_resources(ResourceARNList=[queue_arn], Tags={tag_key: tag_value})[
        "FailedResourcesMap"
    ]
    assert failed == {}, f"TagResources reported failures: {failed!r}"

    expected_mapping = {
        "PaginationToken": "",
        "ResourceTagMappingList": [
            {"ResourceARN": queue_arn, "Tags": [{"Key": tag_key, "Value": tag_value}]}
        ],
    }

    # Positive control: the tag becomes visible to a plain JSON-protocol query. The tagging
    # index lags TagResources, so poll to the exact mapping rather than a weaker "any 200".
    before = _poll_json_mapping(rgta, tag_key, tag_value, expected_mapping)
    assert before == expected_mapping, (
        f"JSON-protocol GetResources returned {before!r}, expected {expected_mapping!r}"
    )

    # The claim: the identical query, framed as RPC v2 CBOR with no X-Amz-Target, is served
    # rather than refused, and returns the same mapping CBOR-encoded.
    akid, secret, token = _caller_credentials(ctx)
    body = _cbor_encode({"TagFilters": [{"Key": tag_key, "Values": [tag_value]}]})
    status, headers, raw = _signed_cbor_post(ctx, body, akid, secret, token)
    assert status == 200, f"RPC v2 CBOR GetResources must be served; got ({status}, {raw!r})"
    assert headers.get("smithy-protocol") == "rpc-v2-cbor", (
        f"a served RPC v2 CBOR response must echo the protocol header; got {headers!r}"
    )
    assert headers.get("content-type") == "application/cbor", (
        f"a served RPC v2 CBOR response must be CBOR-typed; got {headers!r}"
    )
    decoded = _cbor_decode(raw)
    assert decoded == expected_mapping, (
        f"RPC v2 CBOR GetResources decoded to {decoded!r}, expected {expected_mapping!r}"
    )

    # And the control still works afterwards: the CBOR-framed read did not disturb the tag.
    after = rgta.get_resources(TagFilters=[{"Key": tag_key, "Values": [tag_value]}])
    after = {k: after[k] for k in ("PaginationToken", "ResourceTagMappingList")}
    assert after == expected_mapping, (
        f"JSON-protocol GetResources after the CBOR request returned {after!r}, "
        f"expected {expected_mapping!r}"
    )


def _poll_json_mapping(rgta, tag_key, tag_value, expected, *, timeout_s=60.0, interval_s=3.0):
    """Re-query GetResources until it returns exactly ``expected``; the tag index lags TagResources."""
    deadline = time.monotonic() + timeout_s
    while True:
        resp = rgta.get_resources(TagFilters=[{"Key": tag_key, "Values": [tag_value]}])
        mapping = {k: resp[k] for k in ("PaginationToken", "ResourceTagMappingList")}
        if mapping == expected:
            return mapping
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"GetResources never returned {expected!r} within {timeout_s}s; last={mapping!r}"
            )
        time.sleep(interval_s)


def _caller_credentials(ctx):
    """The harness's per-run credentials, via the one sanctioned seam (never the ambient chain)."""
    env = ctx.subprocess_env()
    akid, secret = env.get("AWS_ACCESS_KEY_ID"), env.get("AWS_SECRET_ACCESS_KEY")
    assert akid and secret, "ctx.subprocess_env() carried no credentials to sign with"
    return akid, secret, env.get("AWS_SESSION_TOKEN")


def _signed_cbor_post(ctx, body: bytes, akid, secret, token=None):
    """POST body to the tagging endpoint's RPC v2 CBOR address, SigV4-signed for service
    'tagging'. Returns (status, lowercased headers, raw response bytes)."""
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials

    url = ctx.service_url(f"https://tagging.{ctx.region}.amazonaws.com") + _PATH
    req = AWSRequest(method="POST", url=url, data=body, headers=dict(_HEADERS))
    SigV4Auth(Credentials(akid, secret, token), "tagging", ctx.region).add_auth(req)
    prepared = req.prepare()
    sent_body = bytes(prepared.body) if prepared.body is not None else b""
    http_req = urllib.request.Request(
        url, data=sent_body, method="POST", headers=dict(prepared.headers)
    )
    try:
        with urllib.request.urlopen(http_req, timeout=15) as resp:  # noqa: S310 - fixed https scheme
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as exc:
        headers = {k.lower(): v for k, v in (exc.headers or {}).items()}
        return exc.code, headers, exc.read()


def _cbor_uint(base: int, n: int) -> bytes:
    if n < 24:
        return bytes([base + n])
    if n < 256:
        return bytes([base + 24, n])
    raise ValueError(f"length {n} too large for this encoder")


def _cbor_encode(obj) -> bytes:
    """A minimal CBOR encoder covering the str/list/dict shapes GetResources input needs."""
    if isinstance(obj, str):
        raw = obj.encode("utf-8")
        return _cbor_uint(0x60, len(raw)) + raw
    if isinstance(obj, list):
        out = _cbor_uint(0x80, len(obj))
        for item in obj:
            out += _cbor_encode(item)
        return out
    if isinstance(obj, dict):
        out = _cbor_uint(0xA0, len(obj))
        for k, v in obj.items():
            out += _cbor_encode(k) + _cbor_encode(v)
        return out
    raise TypeError(f"unsupported type for cbor encoding: {type(obj)}")


def _cbor_read_uint(ai: int, data: bytes, pos: int) -> tuple[int, int]:
    if ai < 24:
        return ai, pos
    if ai == 24:
        return data[pos], pos + 1
    if ai == 25:
        return int.from_bytes(data[pos : pos + 2], "big"), pos + 2
    if ai == 26:
        return int.from_bytes(data[pos : pos + 4], "big"), pos + 4
    if ai == 27:
        return int.from_bytes(data[pos : pos + 8], "big"), pos + 8
    raise ValueError(f"unsupported additional info {ai}")


def _cbor_decode_at(data: bytes, pos: int):
    """A minimal CBOR decoder covering the uint/text-string/array/map shapes (definite and
    indefinite length) that a GetResources response needs."""
    lead = data[pos]
    pos += 1
    major, ai = lead >> 5, lead & 0x1F
    if major == 0:
        return _cbor_read_uint(ai, data, pos)
    if major == 3:
        if ai == 31:
            parts = []
            while data[pos] != 0xFF:
                chunk, pos = _cbor_decode_at(data, pos)
                parts.append(chunk)
            return "".join(parts), pos + 1
        n, pos = _cbor_read_uint(ai, data, pos)
        return data[pos : pos + n].decode("utf-8"), pos + n
    if major == 4:
        items = []
        if ai == 31:
            while data[pos] != 0xFF:
                item, pos = _cbor_decode_at(data, pos)
                items.append(item)
            return items, pos + 1
        n, pos = _cbor_read_uint(ai, data, pos)
        for _ in range(n):
            item, pos = _cbor_decode_at(data, pos)
            items.append(item)
        return items, pos
    if major == 5:
        result = {}
        if ai == 31:
            while data[pos] != 0xFF:
                k, pos = _cbor_decode_at(data, pos)
                v, pos = _cbor_decode_at(data, pos)
                result[k] = v
            return result, pos + 1
        n, pos = _cbor_read_uint(ai, data, pos)
        for _ in range(n):
            k, pos = _cbor_decode_at(data, pos)
            v, pos = _cbor_decode_at(data, pos)
            result[k] = v
        return result, pos
    raise ValueError(f"unsupported cbor major type {major} at byte {pos - 1}")


def _cbor_decode(data: bytes):
    value, pos = _cbor_decode_at(data, 0)
    assert pos == len(data), f"trailing cbor bytes after a complete value: {data[pos:]!r}"
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
