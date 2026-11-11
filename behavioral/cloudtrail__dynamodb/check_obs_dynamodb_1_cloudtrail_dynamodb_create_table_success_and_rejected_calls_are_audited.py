"""obs-dynamodb-1-cloudtrail-dynamodb-create-table-success-and-rejected-calls-are-audited."""

from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-dynamodb-1-cloudtrail-dynamodb-create-table-success-and-rejected-calls-are-audited"
GROUP = "eventing"
SERVICES = ["cloudtrail", "dynamodb"]

_EVENT_SOURCE = "dynamodb.amazonaws.com"
_CLOUDTRAIL_BUDGET_S = 1200.0
_POLL_INTERVAL_S = 2.0
_TABLE_ACTIVE_BUDGET_S = 180.0
_TEARDOWN_WAIT_S = 120.0
_PAGE_CEILING = 40


def _call(fn, attempts=8):
    """Invoke fn(), retrying only CloudTrail's LookupEvents throttle (2 TPS per account+region)."""
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ThrottlingException" and i < attempts - 1:
                time.sleep(2.0 * (i + 1))
                continue
            raise
    raise AssertionError("unreachable: _call exhausted its attempts without raising")


def _error(fn):
    """(code, message) of the ClientError fn() raises; raises if the call unexpectedly succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"call unexpectedly SUCCEEDED where an error was required: {resp!r}")


def _delete_table_when_possible(ddb, table_name):
    """Delete the table, waiting out CREATING (DeleteTable then fails ResourceInUseException).
    Idempotent on ResourceNotFoundException; raises when it cannot converge."""
    deadline = time.monotonic() + _TEARDOWN_WAIT_S
    while True:
        try:
            ddb.delete_table(TableName=table_name)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code == "ResourceInUseException" and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            teardown_code = exc.response.get("Error", {}).get("Code", "")
            if teardown_code not in ("ResourceNotFoundException",):
                raise RuntimeError(
                    f"dynamodb table {table_name!r} could not be deleted: {code}"
                ) from exc
            return


def _wait_table_active(ddb, table_name):
    deadline = time.monotonic() + _TABLE_ACTIVE_BUDGET_S
    last = None
    while time.monotonic() < deadline:
        last = ddb.describe_table(TableName=table_name)["Table"]["TableStatus"]
        if last == "ACTIVE":
            return
        time.sleep(3.0)
    raise AssertionError(
        f"table {table_name!r} did not reach ACTIVE within {_TABLE_ACTIVE_BUDGET_S}s; last "
        f"status {last!r}"
    )


def _lookup_dynamodb_events(ct, start, end):
    """Every LookupEvents record with EventSource=dynamodb.amazonaws.com in [start, end], parsed.
    Paged to exhaustion (bounded), each page paced under the 2 TPS LookupEvents limit."""
    out = []
    kw = {
        "StartTime": start,
        "EndTime": end,
        "MaxResults": 50,
        # EventName=CreateTable alone also returns Keyspaces (cassandra.amazonaws.com) records.
        "LookupAttributes": [{"AttributeKey": "EventSource", "AttributeValue": _EVENT_SOURCE}],
    }
    for _ in range(_PAGE_CEILING):
        resp = _call(lambda: ct.lookup_events(**kw))
        for ev in resp.get("Events", []):
            out.append(json.loads(ev["CloudTrailEvent"]))
        nxt = resp.get("NextToken")
        if not nxt:
            break
        kw["NextToken"] = nxt
        time.sleep(0.6)
    return out


def _table_name_of(record):
    params = record.get("requestParameters") or {}
    return params.get("tableName") if isinstance(params, dict) else None


def _summary(records, names):
    """A compact listing of every record naming one of this run's tables, for failure messages."""
    return [
        (r.get("eventName"), _table_name_of(r), r.get("errorCode"), r.get("eventTime"))
        for r in records
        if _table_name_of(r) in names
    ]


@tags(
    "axis:rejection",
    "concern:eventing",
    "concern:negative-classes",
    "cap:c2",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A successful CreateTable and two refused DynamoDB calls each reach CloudTrail event history with
    the exact eventName, table name and, for the refusals, the exact error code returned.
    """
    ddb = ctx.client("dynamodb")
    ct = ctx.client("cloudtrail")
    account = ctx.client("sts").get_caller_identity()["Account"]

    ok_name = ctx.unique_name("sim2real-xsvc-ctddb-ok-")
    missing_name = ctx.unique_name("sim2real-xsvc-ctddb-missing-")
    bad_name = ctx.unique_name("sim2real-xsvc-ctddb-bad-")
    names = {ok_name, missing_name, bad_name}

    window_start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=2)

    # Positive control: a real PAY_PER_REQUEST table.
    created = ddb.create_table(
        TableName=ok_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TableDescription"]
    ctx.on_cleanup(lambda: _delete_table_when_possible(ddb, ok_name))
    created_status = created["TableStatus"]
    assert created["TableName"] == ok_name, (
        f"CreateTable answered TableName {created.get('TableName')!r}, expected {ok_name!r}"
    )
    _wait_table_active(ddb, ok_name)

    code, message = _error(lambda: ddb.describe_table(TableName=missing_name))
    assert code == "ResourceNotFoundException", (
        f"DescribeTable on the never-created table {missing_name!r} answered {code!r} "
        f"({message!r}), expected ResourceNotFoundException"
    )
    assert message == f"Requested resource not found: Table: {missing_name} not found", (
        f"unexpected DescribeTable not-found message: {message!r}"
    )

    # Two HASH keys pass client-side validation and are refused by the service. Teardown is
    # registered before the call so a wrongly accepted create does not leak the table.
    ctx.on_cleanup(lambda: _delete_table_when_possible(ddb, bad_name))
    code, message = _error(lambda: ddb.create_table(
        TableName=bad_name,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "HASH"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    ))
    assert code == "ValidationException", (
        f"CreateTable {bad_name!r} with two HASH keys answered {code!r} ({message!r}), expected "
        f"ValidationException"
    )
    assert message == "Invalid KeySchema: The second KeySchemaElement is not a RANGE key type", (
        f"unexpected two-HASH-keys refusal message: {message!r}"
    )
    code, message = _error(lambda: ddb.describe_table(TableName=bad_name))
    assert code == "ResourceNotFoundException", (
        f"after CreateTable {bad_name!r} was refused, DescribeTable answered {code!r}; expected "
        f"ResourceNotFoundException -- a refused create must leave no table"
    )
    assert message == f"Requested resource not found: Table: {bad_name} not found", (
        f"unexpected DescribeTable not-found message for the refused table: {message!r}"
    )

    # The refusals are issued after the success, so requiring all three rules out index lag.
    t0 = time.monotonic()
    polls = 0
    records = []
    ok_ev = describe_ev = bad_ev = None
    while True:
        polls += 1
        window_end = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
        records = _lookup_dynamodb_events(ct, window_start, window_end)
        ok_ev = next((r for r in records if r.get("eventName") == "CreateTable"
                      and _table_name_of(r) == ok_name), None)
        describe_ev = next((r for r in records if r.get("eventName") == "DescribeTable"
                            and _table_name_of(r) == missing_name), None)
        bad_ev = next((r for r in records if r.get("eventName") == "CreateTable"
                       and _table_name_of(r) == bad_name), None)
        if ok_ev and describe_ev and bad_ev:
            break
        if time.monotonic() - t0 >= _CLOUDTRAIL_BUDGET_S:
            break
        time.sleep(_POLL_INTERVAL_S)
    waited = time.monotonic() - t0

    missing = [label for label, ev in (
        ("CreateTable success " + ok_name, ok_ev),
        ("DescribeTable failure " + missing_name, describe_ev),
        ("CreateTable failure " + bad_name, bad_ev),
    ) if ev is None]
    assert not missing, (
        f"after {polls} LookupEvents polls over {waited:.0f}s (budget {_CLOUDTRAIL_BUDGET_S:.0f}s) "
        f"CloudTrail event history has no record for: {missing!r}. Of {len(records)} "
        f"{_EVENT_SOURCE} records in the window, the last ones seen naming this run's tables "
        f"were (eventName, tableName, errorCode, eventTime): {_summary(records, names)!r}"
    )

    for label, ev in (("success", ok_ev), ("describe-failure", describe_ev),
                      ("create-failure", bad_ev)):
        assert ev["eventSource"] == _EVENT_SOURCE, (
            f"the {label} record's eventSource is {ev.get('eventSource')!r}, expected "
            f"{_EVENT_SOURCE!r}"
        )
        assert ev.get("recipientAccountId") == account, (
            f"the {label} record's recipientAccountId is {ev.get('recipientAccountId')!r}, "
            f"expected the calling account {account!r}"
        )

    assert ok_ev["eventName"] == "CreateTable", f"success record eventName {ok_ev['eventName']!r}"
    assert ok_ev["requestParameters"]["tableName"] == ok_name, (
        f"success record requestParameters.tableName is "
        f"{ok_ev['requestParameters'].get('tableName')!r}, expected {ok_name!r}"
    )
    assert "errorCode" not in ok_ev, (
        f"the SUCCESSFUL CreateTable record carries errorCode {ok_ev.get('errorCode')!r}; a "
        f"successful call's record must have no errorCode key at all"
    )
    table_desc = (ok_ev.get("responseElements") or {}).get("tableDescription") or {}
    assert "tableStatus" in table_desc, (
        f"the successful CreateTable record's responseElements.tableDescription has no "
        f"tableStatus: responseElements={ok_ev.get('responseElements')!r}"
    )
    assert table_desc["tableStatus"] == created_status, (
        f"the audited tableStatus is {table_desc['tableStatus']!r}, but the CreateTable response "
        f"the caller received said {created_status!r}; the record must mirror the response"
    )

    assert describe_ev["eventName"] == "DescribeTable", (
        f"describe-failure record eventName {describe_ev['eventName']!r}"
    )
    assert describe_ev["requestParameters"]["tableName"] == missing_name, (
        f"describe-failure record requestParameters.tableName is "
        f"{describe_ev['requestParameters'].get('tableName')!r}, expected {missing_name!r}"
    )
    assert describe_ev.get("errorCode") == "ResourceNotFoundException", (
        f"the DescribeTable-on-a-missing-table record carries errorCode "
        f"{describe_ev.get('errorCode')!r}, expected ResourceNotFoundException"
    )
    assert isinstance(describe_ev.get("errorMessage"), str) and describe_ev["errorMessage"], (
        f"the DescribeTable failure record's errorMessage is {describe_ev.get('errorMessage')!r}, "
        f"expected a non-empty string"
    )

    assert bad_ev["eventName"] == "CreateTable", f"create-failure record eventName {bad_ev['eventName']!r}"
    assert bad_ev["requestParameters"]["tableName"] == bad_name, (
        f"create-failure record requestParameters.tableName is "
        f"{bad_ev['requestParameters'].get('tableName')!r}, expected {bad_name!r}"
    )
    assert bad_ev.get("errorCode") == "ValidationException", (
        f"the CreateTable-with-two-HASH-keys record carries errorCode {bad_ev.get('errorCode')!r}, "
        f"expected ValidationException"
    )
    assert isinstance(bad_ev.get("errorMessage"), str) and bad_ev["errorMessage"], (
        f"the CreateTable failure record's errorMessage is {bad_ev.get('errorMessage')!r}, "
        f"expected a non-empty string"
    )

    assert ok_ev["eventID"] != bad_ev["eventID"], (
        f"the successful and the refused CreateTable share eventID {ok_ev['eventID']!r}; each "
        f"call must be its own record"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
