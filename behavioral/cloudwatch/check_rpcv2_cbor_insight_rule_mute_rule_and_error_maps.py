"""rpcv2-cbor-insight-rule-mute-rule-and-error-maps."""

from __future__ import annotations

import re
import struct
from datetime import UTC, datetime, timedelta

import requests
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rpcv2-cbor-insight-rule-mute-rule-and-error-maps"
GROUP = "multi-protocol-wire-parity"
SERVICES = ["cloudwatch"]

_SMITHY_SERVICE = "GraniteServiceVersion20100801"


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


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """Over rpc-v2-cbor, a mute rule's lifecycle and insight rule reads answer exact CBOR maps.

    A deleted mute rule, a text Threshold and a zero MaxResults are distinct CBOR error maps.
    Reference: https://smithy.io/2.0/additional-specs/protocols/smithy-rpc-v2.html
    """
    cw = ctx.client("cloudwatch")
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
        assert headers.get("smithy-protocol") == "rpc-v2-cbor", (
            f"CBOR {op} answered headers {headers!r} with {decoded!r}"
        )
        if resp.content:
            assert headers.get("content-type") == "application/cbor", (
                f"CBOR {op} answered headers {headers!r} with {decoded!r}"
            )
        return resp.status_code, decoded

    def cbor_error(op: str, payload: dict):
        status, decoded = cbor_call(op, payload)
        if status == 200:
            raise AssertionError(f"CBOR {op} succeeded with {decoded!r}; AWS refuses it")
        return status, decoded

    alarm = ctx.unique_name("sim2real-behav-cwcbor-alarm-")
    alarm_def = {
        "AlarmName": alarm,
        "Namespace": "Sim2RealBehav/Cbor",
        "MetricName": "Requests",
        "Statistic": "Average",
        "Period": 60,
        "EvaluationPeriods": 1,
        "Threshold": 5.0,
        "ComparisonOperator": "GreaterThanThreshold",
        "ActionsEnabled": False,
        "Tags": [{"Key": "sim2real-behavioral", "Value": CHECK}],
    }
    status, decoded = cbor_call("PutMetricAlarm", alarm_def)
    assert status == 200, f"CBOR PutMetricAlarm answered {status!r}: {decoded!r}"
    ctx.on_cleanup(lambda: _delete_alarm(cw, alarm))

    status, decoded = cbor_call("ListAlarmMuteRules", {"AlarmName": alarm})
    assert (status, decoded) == (200, {"AlarmMuteRuleSummaries": []}), (
        f"CBOR ListAlarmMuteRules answered {status!r} {decoded!r}"
    )

    mute_rule = ctx.unique_name("sim2real-behav-cwcbor-mute-")
    mute_arn = (
        f"arn:{cw.meta.partition}:cloudwatch:{ctx.region}:{ctx.account}:alarm-mute-rule:{mute_rule}"
    )
    window = (datetime.now(UTC) + timedelta(days=365)).strftime("%Y-%m-%dT%H:%M")
    expression = f"at({window})"
    mute_def = {
        "Name": mute_rule,
        "Rule": {"Schedule": {"Expression": expression, "Duration": "PT15M"}},
        "MuteTargets": {"AlarmNames": [alarm]},
        "Tags": [{"Key": "sim2real-behavioral", "Value": CHECK}],
    }
    status, decoded = cbor_call("PutAlarmMuteRule", mute_def)
    assert status == 200, f"CBOR PutAlarmMuteRule answered {status!r}: {decoded!r}"
    ctx.on_cleanup(lambda: _delete_mute_rule(cw, mute_rule))

    status, decoded = cbor_call("GetAlarmMuteRule", {"AlarmMuteRuleName": mute_rule})
    assert status == 200, (
        f"CBOR GetAlarmMuteRule on the just-created rule answered {status!r}: {decoded!r}"
    )
    _assert_epoch_tag(decoded.pop("LastUpdatedTimestamp", None), "GetAlarmMuteRule")
    _assert_creation_id(decoded.pop("CreationId", None), "GetAlarmMuteRule")
    expected_get = {
        "Name": mute_rule,
        "AlarmMuteRuleArn": mute_arn,
        "Rule": {
            "Schedule": {"Expression": expression, "Duration": "PT15M", "Timezone": "UTC"},
        },
        "MuteTargets": {"AlarmNames": [alarm]},
        "Status": "SCHEDULED",
        "MuteType": "one-time",
    }
    assert decoded == expected_get, (
        f"CBOR GetAlarmMuteRule on a rule whose one-time window has not started answered "
        f"{decoded!r}, expected {expected_get!r} -- an unspecified Timezone defaults to UTC"
    )

    status, decoded = cbor_call("ListAlarmMuteRules", {"AlarmName": alarm})
    assert status == 200, (
        f"CBOR ListAlarmMuteRules after PutAlarmMuteRule answered {status!r}: {decoded!r}"
    )
    summaries = decoded.get("AlarmMuteRuleSummaries")
    assert isinstance(summaries, list) and len(summaries) == 1, (
        f"CBOR ListAlarmMuteRules after PutAlarmMuteRule answered {decoded!r}, "
        "expected the one rule"
    )
    _assert_epoch_tag(summaries[0].pop("LastUpdatedTimestamp", None), "ListAlarmMuteRules")
    expected_list = {
        "AlarmMuteRuleSummaries": [
            {"AlarmMuteRuleArn": mute_arn, "Status": "SCHEDULED", "MuteType": "one-time"}
        ]
    }
    assert decoded == expected_list, (
        f"CBOR ListAlarmMuteRules after PutAlarmMuteRule answered {decoded!r}, "
        f"expected {expected_list!r}"
    )

    status, decoded = cbor_call("DeleteAlarmMuteRule", {"AlarmMuteRuleName": mute_rule})
    assert status == 200, f"CBOR DeleteAlarmMuteRule answered {status!r}: {decoded!r}"

    status, decoded = cbor_error("GetAlarmMuteRule", {"AlarmMuteRuleName": mute_rule})
    assert (status, decoded) == (
        400,
        {"__type": "com.amazonaws.cloudwatch.v2010_08_01#ResourceNotFoundException"},
    ), f"CBOR GetAlarmMuteRule on the just-deleted rule answered {status!r} {decoded!r}"

    status, decoded = cbor_call("ListAlarmMuteRules", {"AlarmName": alarm})
    assert (status, decoded) == (200, {"AlarmMuteRuleSummaries": []}), (
        f"CBOR ListAlarmMuteRules after DeleteAlarmMuteRule answered {status!r} {decoded!r}"
    )

    ghost = ctx.unique_name("sim2real-behav-cwcbor-ghost-")
    ctx.on_cleanup(lambda: _delete_alarm(cw, ghost))
    status, decoded = cbor_error(
        "PutMetricAlarm", {**alarm_def, "AlarmName": ghost, "Threshold": "high"}
    )
    assert (status, decoded) == (
        400,
        {"__type": "com.amazon.coral.service#SerializationException"},
    ), f"CBOR PutMetricAlarm with a text Threshold answered {status!r} {decoded!r}"
    assert cw.describe_alarms(AlarmNames=[ghost])["MetricAlarms"] == [], (
        "the refused PutMetricAlarm created an alarm"
    )

    rule = ctx.unique_name("sim2real-behav-cwcbor-rule-")
    definition = (
        '{"Schema":{"Name":"CloudWatchLogRule","Version":1},"AggregateOn":"Count",'
        '"Contribution":{"Keys":["$.ip"],"Filters":[]},"LogFormat":"JSON",'
        f'"LogGroupNames":["/aws/lambda/{rule}"]}}'
    )
    status, decoded = cbor_call(
        "PutInsightRule",
        {
            "RuleName": rule,
            "RuleState": "DISABLED",
            "RuleDefinition": definition,
            "Tags": [{"Key": "sim2real-behavioral", "Value": CHECK}],
        },
    )
    assert status == 200, f"CBOR PutInsightRule answered {status!r}: {decoded!r}"
    ctx.on_cleanup(lambda: _delete_rule(cw, rule))

    mine: list = []
    page: dict = {"MaxResults": 500}
    for _ in range(20):
        status, decoded = cbor_call("DescribeInsightRules", page)
        assert status == 200, f"CBOR DescribeInsightRules answered {status!r}: {decoded!r}"
        mine += [r for r in decoded["InsightRules"] if r["Name"] == rule]
        if mine or "NextToken" not in decoded:
            break
        page = {"MaxResults": 500, "NextToken": decoded["NextToken"]}
    assert mine == [
        {
            "Name": rule,
            "State": "DISABLED",
            "Schema": "CloudWatchLogRule/1",
            "Definition": definition,
            "ManagedRule": False,
            "ApplyOnTransformedLogs": False,
        }
    ], f"CBOR DescribeInsightRules listed {mine!r} for the rule"

    status, decoded = cbor_error("DescribeInsightRules", {"MaxResults": 0})
    assert (status, decoded) == (
        400,
        {
            "__type": "com.amazon.coral.service#InvalidParameterValueException",
            "message": "INVALID_MAX_RESULTS: MaxResults must be greater than 0.",
        },
    ), f"CBOR DescribeInsightRules with MaxResults 0 answered {status!r} {decoded!r}"


_CREATION_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/\d+$")


def _assert_creation_id(value, op: str) -> None:
    assert isinstance(value, str) and _CREATION_ID_RE.match(value), (
        f"CBOR {op} CreationId is {value!r}, not a <uuid>/<epoch-ms> generated id"
    )


def _assert_epoch_tag(value, op: str) -> None:
    assert isinstance(value, _Tagged) and value.tag == 1, (
        f"CBOR {op} LastUpdatedTimestamp is {value!r}, not a CBOR tag-1 epoch timestamp"
    )
    assert type(value.value) is float, (
        f"CBOR {op} LastUpdatedTimestamp tag 1 wraps {type(value.value).__name__}: {value!r}"
    )


def _delete_alarm(cw, name: str) -> None:
    try:
        cw.delete_alarms(AlarmNames=[name])
    except ClientError as err:
        # DeleteAlarms models its not-found error as ResourceNotFound, unlike the mute rule APIs.
        if err.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _delete_rule(cw, name: str) -> None:
    failures = cw.delete_insight_rules(RuleNames=[name])["Failures"]
    not_found = {
        "ExceptionType": "ResourceNotFoundException",
        "FailureCode": "RULE_NAME",
        "FailureDescription": f"Rule {name} does not exist.",
        "FailureResource": name,
    }
    if failures and failures != [not_found]:
        raise AssertionError(f"DeleteInsightRules failed for {name}: {failures!r}")


def _delete_mute_rule(cw, name: str) -> None:
    try:
        cw.delete_alarm_mute_rule(AlarmMuteRuleName=name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
