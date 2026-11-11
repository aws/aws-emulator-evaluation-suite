"""remote-write-query-round-trip."""
from __future__ import annotations

import json
import struct
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "remote-write-query-round-trip"
GROUP = "e2e"
SERVICES = ["amp"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A sample written to an ACTIVE AMP workspace over SigV4-signed, snappy-compressed Prometheus
    remote_write is read back with its exact value by the instant query API: the workspace serves
    Prometheus traffic, not only the control-plane API."""
    amp = ctx.client("amp")
    workspace_id = amp.create_workspace(alias=ctx.unique_name("sim2real-amp-ws-"))["workspaceId"]
    ctx.on_cleanup(lambda: _delete_workspace(ctx, amp, workspace_id))
    _poll_until(
        lambda: amp.describe_workspace(workspaceId=workspace_id)["workspace"]["status"]["statusCode"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
    )
    endpoint = amp.describe_workspace(workspaceId=workspace_id)["workspace"]["prometheusEndpoint"]
    assert endpoint, "workspace has no prometheusEndpoint"

    metric_name = ctx.unique_name("sim2real_amp_metric_").replace("-", "_")
    sample_value = 42.0
    ts_ms = int(time.time() * 1000)

    write_request = _pb_write_request(
        [_pb_timeseries([("__name__", metric_name), ("job", "sim2real-behavioral")], [(sample_value, ts_ms)])]
    )
    compressed = _snappy_compress_literal(write_request)

    status, body, _headers = _signed_request(
        ctx,
        "POST",
        endpoint.rstrip("/") + "/api/v1/remote_write",
        data=compressed,
        headers={
            "Content-Encoding": "snappy",
            "Content-Type": "application/x-protobuf",
            "X-Prometheus-Remote-Write-Version": "0.1.0",
        },
    )
    assert status in (200, 202, 204), f"remote_write failed: HTTP {status}: {body!r}"

    def _query_value():
        q_status, q_body, _ = _signed_request(
            ctx, "GET", endpoint.rstrip("/") + "/api/v1/query", params={"query": metric_name}
        )
        if q_status != 200:
            return None
        payload = json.loads(q_body)
        if payload.get("status") != "success":
            return None
        result = payload.get("data", {}).get("result", [])
        if not result:
            return None
        return float(result[0]["value"][1])

    value = _poll_until(_query_value, lambda v: v is not None, timeout_s=120, interval_s=5)
    assert value == sample_value, f"queried back {value}, expected {sample_value}"


def _snappy_compress_literal(data: bytes) -> bytes:
    """Encode `data` as a valid (uncompressed) snappy block: a varint of the total
    length followed by a run of literal chunks (<=60 bytes each, tag byte low bits
    0b00). No back-references are used -- this is always valid per the snappy format
    spec, just less space-efficient, and avoids a hard dependency on the `python-snappy`
    C extension for a self-contained behavioral check."""

    def _varint(n: int) -> bytes:
        out = bytearray()
        while True:
            b = n & 0x7F
            n >>= 7
            if n:
                out.append(b | 0x80)
            else:
                out.append(b)
                return bytes(out)

    out = bytearray(_varint(len(data)))
    i = 0
    n = len(data)
    while i < n:
        chunk = data[i : i + 60]
        out.append((len(chunk) - 1) << 2)  # literal tag, low 2 bits == 0b00
        out += chunk
        i += len(chunk)
    return bytes(out)


def _pb_varint(n: int) -> bytes:

    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def _pb_tag(field: int, wiretype: int) -> bytes:
    return _pb_varint((field << 3) | wiretype)


def _pb_len_delim(field: int, data: bytes) -> bytes:
    return _pb_tag(field, 2) + _pb_varint(len(data)) + data


def _pb_label(name: str, value: str) -> bytes:
    return _pb_len_delim(1, name.encode("utf-8")) + _pb_len_delim(2, value.encode("utf-8"))


def _pb_sample(value: float, ts_ms: int) -> bytes:
    return (_pb_tag(1, 1) + struct.pack("<d", value)) + (_pb_tag(2, 0) + _pb_varint(ts_ms))


def _pb_timeseries(labels, samples) -> bytes:
    body = b""
    for name, value in labels:
        body += _pb_len_delim(1, _pb_label(name, value))
    for value, ts_ms in samples:
        body += _pb_len_delim(2, _pb_sample(value, ts_ms))
    return body


def _pb_write_request(timeseries_list) -> bytes:
    body = b""
    for ts_bytes in timeseries_list:
        body += _pb_len_delim(1, ts_bytes)
    return body


def _signed_request(ctx, method, url, *, params=None, data=None, headers=None):
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest

    client = ctx.client("amp")
    creds = client._request_signer._credentials
    region = client.meta.region_name
    signing_name = client.meta.service_model.signing_name

    req = AWSRequest(method=method, url=url, data=data, params=params or {}, headers=headers or {})
    SigV4Auth(creds, signing_name, region).add_auth(req)
    prepared = req.prepare()
    body = prepared.body
    if isinstance(body, str):
        body = body.encode("utf-8")

    target, route = ctx.endpoint_route(prepared.url)
    urlreq = urllib.request.Request(target, data=body, method=method, headers=dict(prepared.headers, **route))
    try:
        with urllib.request.urlopen(urlreq, timeout=30) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers or {})


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value



def _delete_workspace(ctx, amp, workspace_id: str) -> None:
    """Teardown: delete the workspace, retrying the documented ConflictException while it is still
    creating or updating; a workspace that is already gone is accepted, anything else raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + min(120.0, ctx.time_left() or 120.0)
    while True:
        try:
            amp.delete_workspace(workspaceId=workspace_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(2.0)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
