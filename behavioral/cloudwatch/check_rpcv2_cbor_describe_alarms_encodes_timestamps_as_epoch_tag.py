"""rpcv2-cbor-describe-alarms-encodes-timestamps-as-epoch-tag."""

from __future__ import annotations

import struct

import requests
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rpcv2-cbor-describe-alarms-encodes-timestamps-as-epoch-tag"
GROUP = "multi-protocol-wire-parity"
SERVICES = ["cloudwatch"]

_SMITHY_SERVICE = "GraniteServiceVersion20100801"
_TIMESTAMPS = (
    "AlarmConfigurationUpdatedTimestamp",
    "StateUpdatedTimestamp",
    "StateTransitionedTimestamp",
)


class _Tagged:
    """A CBOR semantic tag and the item it wraps, kept so the tag itself can be asserted."""

    def __init__(self, tag: int, value) -> None:
        self.tag = tag
        self.value = value

    def __repr__(self) -> str:
        return f"tag({self.tag}, {self.value!r})"


def _cbor_head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    for ai, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * width):
            return bytes([major << 5 | ai]) + n.to_bytes(width, "big")
    raise ValueError(f"integer {n} does not fit a CBOR head")


def _cbor_encode(v) -> bytes:
    """Definite-length CBOR (RFC 8949) for the request shapes this check sends."""
    if isinstance(v, bool):
        return b"\xf5" if v else b"\xf4"
    if isinstance(v, int):
        return _cbor_head(0, v) if v >= 0 else _cbor_head(1, -v - 1)
    if isinstance(v, float):
        return b"\xfb" + struct.pack(">d", v)
    if isinstance(v, str):
        raw = v.encode("utf-8")
        return _cbor_head(3, len(raw)) + raw
    if isinstance(v, list):
        return _cbor_head(4, len(v)) + b"".join(_cbor_encode(x) for x in v)
    if isinstance(v, dict):
        return _cbor_head(5, len(v)) + b"".join(
            _cbor_encode(k) + _cbor_encode(x) for k, x in v.items()
        )
    raise TypeError(f"no CBOR encoding for {type(v).__name__}")


def _cbor_decode(buf: bytes, i: int = 0):
    """Return (value, next_index); definite and indefinite lengths, tags kept as _Tagged."""
    major, ai = buf[i] >> 5, buf[i] & 0x1F
    i += 1
    if major == 7:
        simple = {20: False, 21: True, 22: None}
        if ai in simple:
            return simple[ai], i
        fmt = {25: ">e", 26: ">f", 27: ">d"}.get(ai)
        if fmt is None:
            raise ValueError(f"unsupported CBOR simple value {ai}")
        width = struct.calcsize(fmt)
        return struct.unpack(fmt, buf[i : i + width])[0], i + width
    n = None
    if ai < 24:
        n = ai
    elif ai in (24, 25, 26, 27):
        width = 1 << (ai - 24)
        n, i = int.from_bytes(buf[i : i + width], "big"), i + width
    elif ai != 31:
        raise ValueError(f"bad CBOR additional info {ai} for major type {major}")
    if major == 0:
        return n, i
    if major == 1:
        return -n - 1, i
    if major == 6:
        inner, i = _cbor_decode(buf, i)
        return _Tagged(n, inner), i
    if major in (2, 3):
        if n is None:
            chunks = []
            while buf[i] != 0xFF:
                chunk, i = _cbor_decode(buf, i)
                chunks.append(chunk)
            joined = b"".join(chunks) if major == 2 else "".join(chunks)
            return joined, i + 1
        raw = buf[i : i + n]
        return (raw if major == 2 else raw.decode("utf-8")), i + n
    items = []
    count = 0
    while (buf[i] != 0xFF) if n is None else (count < (n if major == 4 else 2 * n)):
        item, i = _cbor_decode(buf, i)
        items.append(item)
        count += 1
    if n is None:
        i += 1
    if major == 4:
        return items, i
    return dict(zip(items[0::2], items[1::2], strict=True)), i


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Over rpc-v2-cbor, DescribeAlarms gives each alarm timestamp as a CBOR tag-1 epoch.

    The epoch equals the awsJson1.0 instant, beside the exact alarm fields.
    Reference: https://smithy.io/2.0/additional-specs/protocols/smithy-rpc-v2.html
    """
    cw = ctx.client("cloudwatch")

    # Requests are built and signed by hand so they travel over rpc-v2-cbor while the client
    # reads the same alarm back over awsJson1.0.
    creds = cw._request_signer._credentials.get_frozen_credentials()
    endpoint = cw.meta.endpoint_url.rstrip("/")
    signing_name = cw.meta.service_model.signing_name

    def cbor_call(op: str, payload: dict):
        url = f"{endpoint}/service/{_SMITHY_SERVICE}/operation/{op}"
        body = _cbor_encode(payload)
        req = AWSRequest(
            method="POST",
            url=url,
            data=body,
            headers={
                "smithy-protocol": "rpc-v2-cbor",
                "content-type": "application/cbor",
                "accept": "application/cbor",
            },
        )
        SigV4Auth(creds, signing_name, ctx.region).add_auth(req)
        resp = requests.post(
            url, data=body, headers=dict(req.headers.items()), verify=ctx.http_verify, timeout=30
        )
        headers = {k.lower(): v for k, v in resp.headers.items()}
        decoded = _cbor_decode(resp.content)[0] if resp.content else None
        return resp.status_code, headers, decoded

    name = ctx.unique_name("sim2real-behav-cwcbor-")
    status, headers, decoded = cbor_call(
        "PutMetricAlarm",
        {
            "AlarmName": name,
            "Namespace": "Sim2RealBehav/Cbor",
            "MetricName": "Requests",
            "Statistic": "Average",
            "Period": 60,
            "EvaluationPeriods": 1,
            "Threshold": 5.0,
            "ComparisonOperator": "GreaterThanThreshold",
            "ActionsEnabled": False,
            "Tags": [{"Key": "sim2real-behavioral", "Value": CHECK}],
        },
    )
    ctx.on_cleanup(lambda: _delete_alarm(cw, name))
    assert (status, headers.get("smithy-protocol")) == (200, "rpc-v2-cbor"), (
        f"CBOR PutMetricAlarm answered {status!r} {headers!r} {decoded!r}"
    )

    status, headers, decoded = cbor_call("DescribeAlarms", {"AlarmNames": [name]})
    assert status == 200, f"CBOR DescribeAlarms answered {status!r}: {decoded!r}"
    assert (headers.get("content-type"), headers.get("smithy-protocol")) == (
        "application/cbor",
        "rpc-v2-cbor",
    ), f"CBOR DescribeAlarms answered headers {headers!r}"
    assert decoded["CompositeAlarms"] == [], (
        f"expected no composite alarms, got {decoded['CompositeAlarms']!r}"
    )
    alarms = decoded["MetricAlarms"]
    assert len(alarms) == 1, f"expected exactly the one alarm, got {alarms!r}"
    alarm = alarms[0]
    expected = {
        "AlarmName": name,
        "AlarmArn": f"arn:{cw.meta.partition}:cloudwatch:{ctx.region}:{ctx.account}:alarm:{name}",
        "Namespace": "Sim2RealBehav/Cbor",
        "MetricName": "Requests",
        "Statistic": "Average",
        "Period": 60,
        "EvaluationPeriods": 1,
        "Threshold": 5.0,
        "ComparisonOperator": "GreaterThanThreshold",
        "ActionsEnabled": False,
        "StateValue": "INSUFFICIENT_DATA",
    }
    assert {k: alarm.get(k) for k in expected} == expected, f"CBOR alarm fields {alarm!r}"

    json_alarm = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0]
    for field in _TIMESTAMPS:
        stamp = alarm[field]
        assert isinstance(stamp, _Tagged) and stamp.tag == 1, (
            f"{field} is {stamp!r}, not a CBOR tag-1 epoch timestamp"
        )
        assert type(stamp.value) is float, (
            f"{field} tag 1 wraps {type(stamp.value).__name__}: {stamp!r}"
        )
        json_epoch = json_alarm[field].timestamp()
        assert abs(stamp.value - json_epoch) < 0.001, (
            f"{field} is {stamp.value!r} over CBOR but {json_epoch!r} over awsJson1.0"
        )

    status, headers, decoded = cbor_call("DeleteAlarms", {"AlarmNames": [name]})
    assert status == 200, f"CBOR DeleteAlarms answered {status!r}: {decoded!r}"
    status, headers, decoded = cbor_call("DescribeAlarms", {"AlarmNames": [name]})
    assert (status, decoded["MetricAlarms"]) == (200, []), (
        f"DescribeAlarms after DeleteAlarms answered {status!r} {decoded!r}"
    )


def _delete_alarm(cw, name: str) -> None:
    try:
        cw.delete_alarms(AlarmNames=[name])
    except ClientError as err:
        # DeleteAlarms models its not-found error as ResourceNotFound, unlike the mute rule APIs.
        if err.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
