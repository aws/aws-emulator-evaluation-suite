"""rpcv2cbor-and-awsjson-are-one-metric-store."""
from __future__ import annotations

import datetime
import struct
import time

import botocore.model
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

from behavioral_harness import tags

CHECK = "rpcv2cbor-and-awsjson-are-one-metric-store"
GROUP = 'multi-protocol-wire-parity'
SERVICES = ['cloudwatch']

_SMITHY_SERVICE = 'GraniteServiceVersion20100801'
_SIGNING_NAME = 'monitoring'
_INGEST_DEADLINE_S = 420.0  # bound on how long a written datum may take to become readable


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


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:metrics", "concern:representation", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A datum written over smithy-rpc-v2-cbor is the same datum awsJson1.0 reads, both ways."""
    import urllib3

    # botocore resolves CloudWatch to `json` even though its model lists smithy-rpc-v2-cbor first,
    # so the CBOR request is hand-built here with an inline RFC 8949 codec. The custom namespace
    # cannot be deleted (data expires after 15 months); it is unique per run.
    # --- anti-vacuity guard: this check is only cross-protocol while botocore refuses CBOR.
    order = botocore.model.PRIORITY_ORDERED_SUPPORTED_PROTOCOLS
    assert order.index('json') < order.index('smithy-rpc-v2-cbor'), (
        "botocore now prefers smithy-rpc-v2-cbor over json "
        f"({order!r}) -- this check would no longer be putting a second protocol on the wire")
    model = ctx.client("cloudwatch").meta.service_model
    assert 'smithy-rpc-v2-cbor' in (model.metadata.get('protocols') or []), (
        "CloudWatch's model no longer advertises smithy-rpc-v2-cbor: "
        f"{model.metadata.get('protocols')!r}")
    assert model.resolved_protocol == 'json', (
        f"botocore resolved cloudwatch to {model.resolved_protocol!r}, expected 'json' -- "
        "the premise that boto3 cannot emit CBOR here no longer holds")

    cw = ctx.client("cloudwatch")
    raw_creds = cw._request_signer._credentials
    creds = (raw_creds.get_frozen_credentials()
             if hasattr(raw_creds, "get_frozen_credentials") else raw_creds)
    endpoint = cw.meta.endpoint_url.rstrip("/")
    signing_name = cw.meta.service_model.signing_name
    assert signing_name == _SIGNING_NAME, (
        f"cloudwatch signing name is {signing_name!r}, expected {_SIGNING_NAME!r}")
    pool = urllib3.PoolManager()

    def cbor_call(op: str, payload: dict):
        """POST one hand-built rpc-v2-cbor request; return (status, headers, raw, decoded)."""
        url = f"{endpoint}/service/{_SMITHY_SERVICE}/operation/{op}"
        body = _cbor_encode(payload)
        req = AWSRequest(method="POST", url=url, data=body, headers={
            "smithy-protocol": "rpc-v2-cbor",
            "content-type": "application/cbor",
            "accept": "application/cbor",
        })
        SigV4Auth(creds, _SIGNING_NAME, ctx.region).add_auth(req)
        resp = pool.request("POST", url, body=body,
                            headers=dict(req.headers.items()), retries=False)
        raw = resp.data
        decoded = _cbor_decode(raw)[0] if raw else None
        return resp.status, {k.lower(): v for k, v in resp.headers.items()}, raw, decoded, body

    namespace = "sim2real/h1/" + ctx.unique_name("cbor-").rsplit("-", 1)[-1]
    instant = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    bucket_ts = instant.replace(second=0)  # CloudWatch bins a Period=60 query to the minute
    cbor_dims = [{"Name": "writer", "Value": "cbor"}, {"Name": "run", "Value": "a"}]
    json_dims = [{"Name": "writer", "Value": "awsjson"}, {"Name": "run", "Value": "a"}]

    # ---------------------------------------------------------------- CBOR writes datum 1
    status, headers, _raw, decoded, req_body = cbor_call("PutMetricData", {
        "Namespace": namespace,
        "MetricData": [{"MetricName": "M", "Dimensions": cbor_dims,
                        "Timestamp": instant, "Value": 1.5, "Unit": "Count"}],
    })
    assert status == 200, f"CBOR PutMetricData returned {status!r}, body {decoded!r}"
    assert headers.get("smithy-protocol") == "rpc-v2-cbor", (
        "the response did not echo the rpc-v2-cbor discriminator; headers were "
        f"{headers!r} -- the service did not answer on the CBOR protocol")
    assert headers.get("content-type") in (None, "application/cbor"), (
        f"CBOR PutMetricData answered content-type {headers.get('content-type')!r}")

    # The request really was CBOR, not JSON wearing a CBOR content-type: tag 1 for the
    # timestamp and a float64 for the value, and it round-trips through our own decoder.
    assert req_body[:1] == b'\xa2', (
        f"request body did not open with a 2-entry CBOR map: {req_body[:8].hex()!r}")
    assert b'\xc1\xfb' in req_body, (
        f"request carried no CBOR tag-1/float64 timestamp: {req_body.hex()!r}")
    echo = _cbor_decode(req_body)[0]
    assert echo["MetricData"][0]["Value"] == 1.5, (
        f"our own CBOR encoder does not round-trip 1.5: {echo!r}")
    assert echo["MetricData"][0]["Timestamp"] == instant, (
        f"tag-1 timestamp did not round-trip: {echo['MetricData'][0]['Timestamp']!r} "
        f"!= {instant!r}")

    # ------------------------------------------------- awsJson1.0 (boto3) reads datum 1 back
    def stats(dims):
        return cw.get_metric_statistics(
            Namespace=namespace, MetricName="M", Dimensions=dims,
            StartTime=instant - datetime.timedelta(minutes=5),
            EndTime=instant + datetime.timedelta(minutes=5),
            Period=60, Statistics=["Sum", "Maximum"])["Datapoints"]

    deadline = time.time() + _INGEST_DEADLINE_S
    points = []
    while time.time() < deadline:
        points = stats(cbor_dims)
        if points:
            break
        time.sleep(5.0)
    assert len(points) == 1, (
        f"awsJson1.0 GetMetricStatistics saw {len(points)} datapoints for the CBOR write "
        f"within {_INGEST_DEADLINE_S}s: {points!r} -- the two protocols are not one store")
    point = points[0]
    assert point["Sum"] == 1.5 and point["Maximum"] == 1.5, (
        f"the value written as a CBOR float64 came back as {point!r}, expected 1.5")
    assert point["Unit"] == "Count", (
        f"the Unit enum written over CBOR came back as {point['Unit']!r}")
    got_ts = point["Timestamp"].astimezone(datetime.timezone.utc).replace(tzinfo=None)
    assert got_ts == bucket_ts.replace(tzinfo=None), (
        f"the CBOR tag-1 timestamp landed in bucket {got_ts!r}, expected "
        f"{bucket_ts.replace(tzinfo=None)!r} (sent {instant!r}) -- the tag was not decoded as "
        "an epoch instant")

    # Dimension identity is exact: a partial dimension set is a DIFFERENT metric, so a CBOR
    # decoder that dropped or duplicated a map member would be visible here.
    assert stats(cbor_dims[:1]) == [], (
        f"querying only {cbor_dims[:1]!r} returned datapoints: {stats(cbor_dims[:1])!r} -- "
        "the dimension set written over CBOR is not the metric's identity")
    assert stats([]) == [], (
        f"querying with no dimensions returned datapoints: {stats([])!r}")
    assert stats(json_dims) == [], (
        f"the awsJson dimension set already has data before it was written: "
        f"{stats(json_dims)!r}")

    # ------------------------------------------ reverse: awsJson1.0 writes, CBOR reads back
    cw.put_metric_data(Namespace=namespace, MetricData=[
        {"MetricName": "M", "Dimensions": json_dims,
         "Timestamp": instant, "Value": 2.25, "Unit": "Count"}])
    deadline = time.time() + _INGEST_DEADLINE_S
    while time.time() < deadline:
        if stats(json_dims):
            break
        time.sleep(5.0)

    query = {
        "MetricDataQueries": [
            {"Id": "c", "ReturnData": True,
             "MetricStat": {"Metric": {"Namespace": namespace, "MetricName": "M",
                                       "Dimensions": cbor_dims},
                            "Period": 60, "Stat": "Sum"}},
            {"Id": "j", "ReturnData": True,
             "MetricStat": {"Metric": {"Namespace": namespace, "MetricName": "M",
                                       "Dimensions": json_dims},
                            "Period": 60, "Stat": "Sum"}},
        ],
        "StartTime": instant - datetime.timedelta(minutes=5),
        "EndTime": instant + datetime.timedelta(minutes=5),
    }
    status, headers, raw, decoded, _ = cbor_call("GetMetricData", query)
    assert status == 200, f"CBOR GetMetricData returned {status!r}: {decoded!r}"
    assert headers.get("content-type") == "application/cbor", (
        f"CBOR GetMetricData answered content-type {headers.get('content-type')!r}, "
        "so the response was not CBOR")
    assert b'\xc1' in raw, f"CBOR response carried no tag-1 timestamp: {raw.hex()!r}"
    series = {r["Id"]: r for r in decoded["MetricDataResults"]}
    assert set(series) == {"c", "j"}, f"CBOR GetMetricData returned ids {sorted(series)!r}"
    assert series["c"]["Values"] == [1.5], (
        f"CBOR read of the CBOR-written datum gave {series['c']!r}, expected Values [1.5]")
    assert series["j"]["Values"] == [2.25], (
        f"CBOR read of the awsJson-written datum gave {series['j']!r}, expected Values [2.25] "
        "-- the two protocols do not share one store")
    for sid in ("c", "j"):
        ts = series[sid]["Timestamps"][0]
        assert isinstance(ts, datetime.datetime), (
            f"series {sid} Timestamps[0] decoded as {type(ts).__name__}, not a datetime -- "
            f"the CBOR tag-1 wrapper was missing: {series[sid]!r}")
        assert ts.astimezone(datetime.timezone.utc).replace(tzinfo=None) == \
            bucket_ts.replace(tzinfo=None), (
            f"series {sid} timestamp {ts!r} != expected bucket "
            f"{bucket_ts.replace(tzinfo=None)!r}")

    # One instant, two protocols, two readers: the awsJson reader and the CBOR reader agree.
    json_side = stats(json_dims)
    assert len(json_side) == 1 and json_side[0]["Sum"] == 2.25, (
        f"awsJson read of its own datum gave {json_side!r}")
    assert json_side[0]["Timestamp"].astimezone(datetime.timezone.utc).replace(tzinfo=None) == \
        series["j"]["Timestamps"][0].astimezone(datetime.timezone.utc).replace(tzinfo=None), (
        f"the two protocols disagree on the instant: awsJson {json_side[0]['Timestamp']!r} "
        f"vs CBOR {series['j']['Timestamps'][0]!r}")

    # CBOR GetMetricStatistics: the same enum and the same value through a third route.
    status, headers, raw, decoded, _ = cbor_call("GetMetricStatistics", {
        "Namespace": namespace, "MetricName": "M", "Dimensions": cbor_dims,
        "StartTime": instant - datetime.timedelta(minutes=5),
        "EndTime": instant + datetime.timedelta(minutes=5),
        "Period": 60, "Statistics": ["Sum", "Maximum"]})
    assert status == 200, f"CBOR GetMetricStatistics returned {status!r}: {decoded!r}"
    dps = decoded["Datapoints"]
    assert len(dps) == 1, f"CBOR GetMetricStatistics returned {dps!r}"
    assert dps[0]["Sum"] == 1.5 and dps[0]["Maximum"] == 1.5, f"CBOR datapoint {dps[0]!r}"
    assert dps[0]["Unit"] == "Count", f"CBOR Unit came back {dps[0]['Unit']!r}"
    assert decoded["Label"] == "M", f"CBOR Label came back {decoded['Label']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
