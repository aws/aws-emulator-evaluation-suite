"""stop-metric-streams-missing-required-parameter-rejected."""
from __future__ import annotations

import struct

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

from behavioral_harness import tags

CHECK = "stop-metric-streams-missing-required-parameter-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]

_SMITHY_SERVICE = "GraniteServiceVersion20100801"
_SIGNING_NAME = "monitoring"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """StopMetricStreams with Names present returns 200, and a signed request with Names absent
    fails with HTTP 400 ValidationException whose message names the null 'names' member."""
    cw = ctx.client("cloudwatch")

    # Positive control: the same operation, with Names present, succeeds -- proves this
    # isn't "StopMetricStreams always fails" and isolates the assertion below to the
    # omitted-member case specifically.
    control = cw.stop_metric_streams(Names=[ctx.unique_name("sim2real-cwmsreq-missing-")])
    assert control["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"StopMetricStreams with a present Names list returned "
        f"{control['ResponseMetadata']['HTTPStatusCode']}, expected 200"
    )

    status, decoded = _raw_post(cw, ctx.region, "StopMetricStreams", b"\xa0")  # {} -- no Names key at all
    assert status == 400, (
        f"omitting Names entirely from StopMetricStreams gave HTTP {status}, expected 400: {decoded!r}"
    )
    assert isinstance(decoded, dict), f"error body was not a CBOR map: {decoded!r}"
    etype = decoded.get("__type", "")
    code = etype.rsplit("#", 1)[-1]
    assert code == "ValidationException", (
        f"omitting Names entirely gave error {code!r}, expected ValidationException: {decoded!r}"
    )
    message = decoded.get("message") or decoded.get("Message") or ""
    assert "names" in message.lower(), f"error message did not name the missing parameter: {message!r}"
    assert "null" in message.lower(), (
        f"error message did not describe a null/missing-member violation: {message!r}"
    )


def _cbor_decode(buf: bytes, i: int = 0):
    """Minimal CBOR (RFC 8949) decoder: enough for a rpc-v2-cbor error body (a map of
    strings), including the indefinite-length maps real CloudWatch answers with."""
    ib = buf[i]
    major, ai = ib >> 5, ib & 0x1F
    i += 1
    n = None
    if major != 7:
        if ai < 24:
            n = ai
        elif ai == 24:
            n, i = buf[i], i + 1
        elif ai == 25:
            n, i = int.from_bytes(buf[i:i + 2], "big"), i + 2
        elif ai == 26:
            n, i = int.from_bytes(buf[i:i + 4], "big"), i + 4
        elif ai == 27:
            n, i = int.from_bytes(buf[i:i + 8], "big"), i + 8
        elif ai != 31:
            raise ValueError(f"bad additional-info {ai} for major {major}")
    if major == 0:
        return n, i
    if major == 1:
        return -n - 1, i
    if major in (2, 3):
        if n is None:
            out = b"" if major == 2 else ""
            while buf[i] != 0xFF:
                chunk, i = _cbor_decode(buf, i)
                out += chunk
            return out, i + 1
        raw = buf[i:i + n]
        return (raw if major == 2 else raw.decode("utf8")), i + n
    if major == 4:
        out = []
        if n is None:
            while buf[i] != 0xFF:
                item, i = _cbor_decode(buf, i)
                out.append(item)
            return out, i + 1
        for _ in range(n):
            item, i = _cbor_decode(buf, i)
            out.append(item)
        return out, i
    if major == 5:
        out = {}
        if n is None:
            while buf[i] != 0xFF:
                key, i = _cbor_decode(buf, i)
                val, i = _cbor_decode(buf, i)
                out[key] = val
            return out, i + 1
        for _ in range(n):
            key, i = _cbor_decode(buf, i)
            val, i = _cbor_decode(buf, i)
            out[key] = val
        return out, i
    if major == 6:
        val, i = _cbor_decode(buf, i)
        return val, i
    if ai == 20:
        return False, i
    if ai == 21:
        return True, i
    if ai == 22:
        return None, i
    if ai == 25:
        return struct.unpack(">e", buf[i:i + 2])[0], i + 2
    if ai == 26:
        return struct.unpack(">f", buf[i:i + 4])[0], i + 4
    if ai == 27:
        return struct.unpack(">d", buf[i:i + 8])[0], i + 8
    raise ValueError(f"unsupported simple value {ai}")


def _raw_post(cw_client, region: str, operation: str, body: bytes):
    """POST a hand-signed rpc-v2-cbor request straight to CloudWatch's smithy service path,
    bypassing botocore's client-side required-parameter enforcement, and decode the
    CBOR-encoded error body. Uses the same endpoint/credentials the check's boto3 client is
    already wired to, so it works unmodified against real AWS or an emulator target."""
    import urllib3

    raw_creds = cw_client._request_signer._credentials
    creds = (
        raw_creds.get_frozen_credentials()
        if hasattr(raw_creds, "get_frozen_credentials")
        else raw_creds
    )
    endpoint = cw_client.meta.endpoint_url.rstrip("/")
    url = f"{endpoint}/service/{_SMITHY_SERVICE}/operation/{operation}"
    headers = {
        "content-type": "application/cbor",
        "accept": "application/cbor",
        "smithy-protocol": "rpc-v2-cbor",
    }
    req = AWSRequest(method="POST", url=url, data=body, headers=headers)
    SigV4Auth(creds, _SIGNING_NAME, region).add_auth(req)
    pool = urllib3.PoolManager()
    resp = pool.request("POST", url, body=body, headers=dict(req.headers.items()), retries=False)
    decoded = None
    if resp.data and (resp.headers.get("Content-Type") or "").startswith("application/cbor"):
        decoded = _cbor_decode(resp.data)[0]
    return resp.status, decoded


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
