"""rpcv2cbor-protocol-discriminator-and-framing-refusals."""
from __future__ import annotations

import datetime
import struct
import time

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

from behavioral_harness import tags

CHECK = "rpcv2cbor-protocol-discriminator-and-framing-refusals"
GROUP = 'multi-protocol-wire-parity-rejected'
SERVICES = ['cloudwatch']

_SMITHY_SERVICE = 'GraniteServiceVersion20100801'
_SIGNING_NAME = 'monitoring'
_CORAL = 'com.amazon.coral.service#'
_INGEST_DEADLINE_S = 420.0  # bound on how long a written datum may take to become readable


def _coral_code(status: int, decoded, label: str) -> str:
    """The `__type` suffix of a CBOR error body. Raises if the call unexpectedly SUCCEEDED --
    a target accepting input real AWS rejects is the strongest possible signal and must
    never be reported as a mere code mismatch."""
    if status == 200:
        raise AssertionError(
            f"{label}: real CloudWatch refuses this, the target answered 200 with {decoded!r}")
    assert isinstance(decoded, dict), f"{label}: error body was not a CBOR map: {decoded!r}"
    etype = decoded.get("__type")
    assert isinstance(etype, str) and etype.startswith(_CORAL), (
        f"{label}: error __type was {etype!r}, expected a {_CORAL!r}-namespaced name")
    return etype[len(_CORAL):]


# --------------------------------------------------------------------------- CBOR (RFC 8949)
def _cbor_head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    if n < 0x100:
        return bytes([major << 5 | 24, n])
    if n < 0x10000:
        return bytes([major << 5 | 25]) + n.to_bytes(2, 'big')
    if n < 0x100000000:
        return bytes([major << 5 | 26]) + n.to_bytes(4, 'big')
    return bytes([major << 5 | 27]) + n.to_bytes(8, 'big')


def _cbor_encode(v) -> bytes:
    """Definite-length CBOR. Datetimes become tag 1 (epoch) over a float64, per rpc-v2-cbor."""
    if isinstance(v, bool):
        return b'\xf5' if v else b'\xf4'
    if v is None:
        return b'\xf6'
    if isinstance(v, datetime.datetime):
        return b'\xc1' + b'\xfb' + struct.pack('>d', v.timestamp())
    if isinstance(v, int):
        return _cbor_head(0, v) if v >= 0 else _cbor_head(1, -v - 1)
    if isinstance(v, float):
        return b'\xfb' + struct.pack('>d', v)
    if isinstance(v, str):
        raw = v.encode('utf8')
        return _cbor_head(3, len(raw)) + raw
    if isinstance(v, bytes):
        return _cbor_head(2, len(v)) + v
    if isinstance(v, list):
        return _cbor_head(4, len(v)) + b''.join(_cbor_encode(x) for x in v)
    if isinstance(v, dict):
        return _cbor_head(5, len(v)) + b''.join(
            _cbor_encode(k) + _cbor_encode(x) for k, x in v.items())
    raise TypeError(f"no CBOR encoding for {type(v).__name__}")


def _cbor_decode(buf: bytes, i: int = 0):
    """Return (value, next_index). Handles indefinite-length maps/arrays, which real CloudWatch
    uses in its CBOR responses (measured: responses open with 0xbf and 0x9f)."""
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
            n, i = int.from_bytes(buf[i:i + 2], 'big'), i + 2
        elif ai == 26:
            n, i = int.from_bytes(buf[i:i + 4], 'big'), i + 4
        elif ai == 27:
            n, i = int.from_bytes(buf[i:i + 8], 'big'), i + 8
        elif ai != 31:
            raise ValueError(f"bad additional-info {ai} for major {major}")
    if major == 0:
        return n, i
    if major == 1:
        return -n - 1, i
    if major in (2, 3):
        if n is None:  # indefinite-length string: concatenate the chunks
            out = b'' if major == 2 else ''
            while buf[i] != 0xFF:
                chunk, i = _cbor_decode(buf, i)
                out += chunk
            return out, i + 1
        raw = buf[i:i + n]
        return (raw if major == 2 else raw.decode('utf8')), i + n
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
        if n == 1:
            return datetime.datetime.fromtimestamp(val, datetime.timezone.utc), i
        return val, i
    if ai == 20:
        return False, i
    if ai == 21:
        return True, i
    if ai == 22:
        return None, i
    if ai == 25:
        return struct.unpack('>e', buf[i:i + 2])[0], i + 2
    if ai == 26:
        return struct.unpack('>f', buf[i:i + 4])[0], i + 4
    if ai == 27:
        return struct.unpack('>d', buf[i:i + 8])[0], i + 8
    raise ValueError(f"unsupported simple value {ai}")


@tags("axis:rejection", "cap:c2", "concern:metrics", "concern:negative-classes", "concern:representation", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """The smithy-protocol header routes rpc-v2-cbor; off-route and malformed frames are refused."""
    import urllib3

    # botocore cannot emit rpc-v2-cbor for CloudWatch, so requests are hand-built with an inline
    # RFC 8949 codec. The control's custom namespace cannot be deleted; it is unique per run.
    cw = ctx.client("cloudwatch")
    raw_creds = cw._request_signer._credentials
    creds = (raw_creds.get_frozen_credentials()
             if hasattr(raw_creds, "get_frozen_credentials") else raw_creds)
    endpoint = cw.meta.endpoint_url.rstrip("/")
    pool = urllib3.PoolManager()

    def post(op: str, body: bytes, *, protocol="rpc-v2-cbor", content_type="application/cbor",
             service=_SMITHY_SERVICE, extra=None, break_signature=False):
        """POST to the rpc-v2-cbor route; return (status, headers, raw_bytes, decoded_or_None)."""
        url = f"{endpoint}/service/{service}/operation/{op}"
        headers = {"content-type": content_type, "accept": "application/cbor"}
        if protocol is not None:
            headers["smithy-protocol"] = protocol
        if extra:
            headers.update(extra)
        req = AWSRequest(method="POST", url=url, data=body, headers=headers)
        SigV4Auth(creds, _SIGNING_NAME, ctx.region).add_auth(req)
        sent = dict(req.headers.items())
        if break_signature:
            sent["Authorization"] = sent["Authorization"][:-4] + "0000"
        resp = pool.request("POST", url, body=body, headers=sent, retries=False)
        raw = resp.data
        decoded = None
        if raw and (resp.headers.get("Content-Type") or "").startswith("application/cbor"):
            decoded = _cbor_decode(raw)[0]
        return resp.status, {k.lower(): v for k, v in resp.headers.items()}, raw, decoded

    namespace = "sim2real/h1/" + ctx.unique_name("cborneg-").rsplit("-", 1)[-1]
    instant = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    dims = [{"Name": "writer", "Value": "cbor"}]
    well_formed = {"Namespace": namespace,
                   "MetricData": [{"MetricName": "M", "Dimensions": dims,
                                   "Timestamp": instant, "Value": 4.5, "Unit": "Count"}]}
    good_body = _cbor_encode(well_formed)

    def stats(dimensions):
        return cw.get_metric_statistics(
            Namespace=namespace, MetricName="M", Dimensions=dimensions,
            StartTime=instant - datetime.timedelta(minutes=5),
            EndTime=instant + datetime.timedelta(minutes=5),
            Period=60, Statistics=["Sum"])["Datapoints"]

    # ---- 1. the discriminator IS the route. Drop the header and the same URL 404s in XML.
    status, headers, raw, decoded = post("PutMetricData", good_body, protocol=None)
    assert status == 404, (
        f"omitting smithy-protocol gave {status!r}, expected 404 -- the header is the "
        f"routing discriminator on real CloudWatch. body {raw[:200]!r}")
    assert "smithy-protocol" not in headers, (
        f"a request with no smithy-protocol got a CBOR-protocol response: {headers!r}")
    assert raw.strip() == b"<UnknownOperationException/>", (
        f"expected the bare XML UnknownOperationException body real CloudWatch returns off "
        f"the CBOR route, got {raw[:200]!r}")
    assert decoded is None, f"the off-route 404 was CBOR-encoded: {decoded!r}"

    # ---- 2. a wrong discriminator value is off-route too, not a CBOR-level error.
    status, _headers, raw, _decoded = post("PutMetricData", good_body, protocol="rpc-v2-json")
    assert status == 404, (
        f"smithy-protocol: rpc-v2-json gave {status!r}, expected 404: {raw[:200]!r}")
    assert raw.strip() == b"<UnknownOperationException/>", (
        f"expected the XML UnknownOperationException body, got {raw[:200]!r}")

    # ---- 3. on the route, an unknown operation is a CBOR-encoded 404.
    status, headers, raw, decoded = post("NoSuchOperationAtAll", _cbor_encode({}))
    assert status == 404, f"unknown operation gave {status!r}: {raw[:200]!r}"
    assert headers.get("smithy-protocol") == "rpc-v2-cbor", (
        f"an on-route 404 did not echo the discriminator: {headers!r}")
    code = _coral_code(status, decoded, "unknown operation on the CBOR route")
    assert code == "UnknownOperationException", (
        f"unknown operation gave __type suffix {code!r}, expected UnknownOperationException")

    # ---- 4. a wrong service name in the path is the same refusal, still on the CBOR route.
    status, _headers, raw, decoded = post("PutMetricData", good_body, service="CloudWatch")
    assert status == 404, f"wrong service name gave {status!r}: {raw[:200]!r}"
    code = _coral_code(status, decoded, "wrong smithy service name in path")
    assert code == "UnknownOperationException", (
        f"wrong service name gave {code!r}, expected UnknownOperationException")

    # ---- 5. an unparseable CBOR frame is a SerializationException, in CBOR.
    status, headers, raw, decoded = post("PutMetricData", b"\xff\xff\xff\xff")
    assert status == 400, f"garbage CBOR gave {status!r}: {raw[:200]!r}"
    assert headers.get("content-type") == "application/cbor", (
        f"the framing error was not returned as CBOR: {headers!r}")
    code = _coral_code(status, decoded, "unparseable CBOR frame")
    assert code == "SerializationException", (
        f"garbage CBOR gave {code!r}, expected SerializationException")

    # ---- 6. a JSON body on the CBOR route is refused, not transcoded. A target that
    #         forwards the CBOR route to its JSON handler accepts this and fails here.
    status, _headers, raw, decoded = post(
        "PutMetricData", b'{"Namespace":"x","MetricData":[]}')
    assert status == 400, (
        f"a JSON body on the CBOR route gave {status!r}, expected 400 -- the route is not a "
        f"JSON alias: {raw[:200]!r}")
    code = _coral_code(status, decoded, "JSON body on the CBOR route")
    assert code == "SerializationException", (
        f"a JSON body gave {code!r}, expected SerializationException")

    # ---- 7. an empty body is a distinct, message-bearing SerializationException.
    status, _headers, raw, decoded = post("PutMetricData", b"")
    assert status == 400, f"empty body gave {status!r}: {raw[:200]!r}"
    code = _coral_code(status, decoded, "empty CBOR body")
    assert code == "SerializationException", f"empty body gave {code!r}"
    assert decoded.get("Message") == "Got an unexpected empty value.", (
        f"empty body message was {decoded.get('Message')!r}; real CloudWatch says "
        "'Got an unexpected empty value.' -- and it uses the capitalised key 'Message' here "
        f"while its validation errors use lowercase 'message'. body {decoded!r}")

    # ---- 8. structurally valid CBOR of the wrong SHAPE is still a serialization failure.
    status, _headers, raw, decoded = post(
        "PutMetricData", _cbor_encode({"Namespace": 5, "MetricData": []}))
    assert status == 400, f"Namespace as a CBOR integer gave {status!r}: {raw[:200]!r}"
    code = _coral_code(status, decoded, "CBOR integer where a string member is modeled")
    assert code == "SerializationException", (
        f"a type-mismatched CBOR member gave {code!r}, expected SerializationException")

    # ---- 9. a decodable frame that omits a required member reaches VALIDATION, which is a
    #         different error class than framing -- and its message leaks the AWS Query
    #         protocol's `member.N` naming through the CBOR wire.
    status, _headers, raw, decoded = post(
        "PutMetricData", _cbor_encode({"Namespace": namespace}))
    assert status == 400, f"missing MetricData gave {status!r}: {raw[:200]!r}"
    code = _coral_code(status, decoded, "MetricData omitted")
    assert code == "MissingRequiredParameterException", (
        f"omitting MetricData gave {code!r}, expected MissingRequiredParameterException -- "
        "a validation failure, not a framing one")
    assert decoded.get("message") == (
        "At least one MetricDatum object must be present in the request."), (
        f"message was {decoded.get('message')!r}")

    status, _headers, raw, decoded = post("PutMetricData", _cbor_encode(
        {"Namespace": namespace, "MetricData": [{"Value": 1.0}]}))
    assert status == 400, f"missing MetricName gave {status!r}: {raw[:200]!r}"
    code = _coral_code(status, decoded, "MetricName omitted")
    assert code == "MissingRequiredParameterException", (
        f"omitting MetricName gave {code!r}, expected MissingRequiredParameterException")
    assert decoded.get("message") == (
        "The parameter MetricData.member.1.MetricName is required."), (
        f"message was {decoded.get('message')!r} -- real CloudWatch names the missing member "
        "with the AWS Query protocol's `member.N` path even over rpc-v2-cbor, which is the "
        "single hardest detail here to arrive at by accident")

    # ---- 10. a broken signature is refused before any of the above, and differently.
    status, headers, raw, decoded = post("PutMetricData", good_body, break_signature=True)
    assert status == 403, f"a tampered signature gave {status!r}: {raw[:200]!r}"
    code = _coral_code(status, decoded, "tampered SigV4 signature")
    assert code == "InvalidSignatureException", (
        f"a tampered signature gave {code!r}, expected InvalidSignatureException")
    assert code not in ("SerializationException", "MissingRequiredParameterException"), (
        "an auth failure is not distinguished from a framing or validation failure")

    # ---- 11. effect-absent: eleven refused requests wrote nothing.
    assert stats(dims) == [], (
        f"a refused request created a datapoint before the control write: {stats(dims)!r}")

    # ---- 12. positive control: the SAME route, headers and codec, well formed, succeeds --
    #          so every refusal above is about the input and not about a broken client.
    status, headers, raw, decoded = post("PutMetricData", good_body)
    assert status == 200, (
        f"the well-formed control write was refused with {status!r} {decoded!r} -- the "
        "refusals above cannot be attributed to the input")
    assert headers.get("smithy-protocol") == "rpc-v2-cbor", (
        f"the control response did not echo the discriminator: {headers!r}")

    deadline = time.time() + _INGEST_DEADLINE_S
    points = []
    while time.time() < deadline:
        points = stats(dims)
        if points:
            break
        time.sleep(5.0)
    assert len(points) == 1 and points[0]["Sum"] == 4.5, (
        f"the control datum written over CBOR was not readable over awsJson1.0 within "
        f"{_INGEST_DEADLINE_S}s: {points!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
