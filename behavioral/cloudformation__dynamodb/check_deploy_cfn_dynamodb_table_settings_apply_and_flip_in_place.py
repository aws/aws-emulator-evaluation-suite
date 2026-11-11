"""deploy-cfn-dynamodb-table-settings-apply-and-flip-in-place."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-cfn-dynamodb-table-settings-apply-and-flip-in-place"
GROUP = "deploy"
SERVICES = ["cloudformation", "dynamodb"]

# Each flipped setting is read from its own DynamoDB describe call. TableClass and TTL stay as
# created: changing either keeps the stack UPDATE_IN_PROGRESS for about half an hour.
_TABLE_CLASS = "STANDARD_INFREQUENT_ACCESS"
_TTL_ATTRIBUTE = "expiresAt"
_SETTLE_S = 300.0


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation",
      "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A CloudFormation DynamoDB table gets every declared setting on create (KMS SSE, TTL, PITR,
    contributor insights, infrequent-access class, a KEYS_ONLY GSI); an UpdateStack turning SSE, PITR
    and contributor insights off applies in place, keeping physical id, TableId, TTL, class and item."""
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-xsvc-cfnset-")

    stack_id = cfn.create_stack(StackName=ctx.unique_name("sim2real-xsvc-cfnset-stk-"),
                                TemplateBody=_template(table, on=True),
                                Tags=[{"Key": "sim2real", "Value": CHECK}])["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_id))
    stack = _poll_stack(cfn, stack_id, _CREATE_TERMINAL)
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"the table stack must deploy; got {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}")
    physical = _physical_id(cfn, stack_id, "Table")
    assert physical == table, f"the table's physical id must be its declared name, got {physical!r}"

    before = ddb.describe_table(TableName=table)["Table"]
    sse = before.get("SSEDescription", {})
    assert (sse.get("Status"), sse.get("SSEType")) == ("ENABLED", "KMS"), (
        f"SSESpecification SSEEnabled=true must give KMS encryption, DescribeTable says status "
        f"{sse.get('Status')!r} type {sse.get('SSEType')!r}")
    assert sse.get("KMSMasterKeyArn", "").startswith(f"arn:aws:kms:{ctx.region}:{ctx.account}:key/"), (
        f"the KMS key must be a key in this account and region, got a value of shape "
        f"{sse.get('KMSMasterKeyArn', '')[:20]!r}...")
    assert before.get("TableClassSummary", {}).get("TableClass") == _TABLE_CLASS, (
        f"TableClass must be {_TABLE_CLASS}, got {before.get('TableClassSummary')!r}")
    assert before.get("BillingModeSummary", {}).get("BillingMode") == "PAY_PER_REQUEST", (
        f"BillingMode must be PAY_PER_REQUEST, got {before.get('BillingModeSummary')!r}")
    gsis = [(g["IndexName"], g["KeySchema"], g["Projection"]["ProjectionType"])
            for g in before.get("GlobalSecondaryIndexes", [])]
    assert gsis == [("byGk", [{"AttributeName": "gk", "KeyType": "HASH"}], "KEYS_ONLY")], (
        f"the declared KEYS_ONLY GSI must exist as declared, got {gsis!r}")
    _assert_switches(ddb, table, on=True)

    item = {"pk": {"S": "survives"}, "gk": {"S": "g"}, "v": {"N": "42"}}
    ddb.put_item(TableName=table, Item=item)

    cfn.update_stack(StackName=stack_id, TemplateBody=_template(table, on=False))
    stack = _poll_stack(cfn, stack_id, _UPDATE_TERMINAL)
    assert stack["StackStatus"] == "UPDATE_COMPLETE", (
        f"turning the settings off must update the stack; got {stack['StackStatus']!r}: "
        f"{stack.get('StackStatusReason')!r}")
    assert _physical_id(cfn, stack_id, "Table") == physical, (
        "the physical resource id changed across the update, so the table was replaced")

    after = ddb.describe_table(TableName=table)["Table"]
    assert after["TableId"] == before["TableId"], "the TableId changed: the table was replaced"
    assert "SSEDescription" not in after, (
        f"SSEEnabled=false returns the table to the AWS-owned key, which DescribeTable reports by "
        f"omitting SSEDescription; it still says status "
        f"{after.get('SSEDescription', {}).get('Status')!r}")
    assert after.get("TableClassSummary", {}).get("TableClass") == _TABLE_CLASS, (
        f"the unchanged TableClass must stay {_TABLE_CLASS}, got {after.get('TableClassSummary')!r}")
    _assert_switches(ddb, table, on=False)

    got = ddb.get_item(TableName=table, Key={"pk": {"S": "survives"}}, ConsistentRead=True).get("Item")
    assert got == item, f"the item written before the update must survive it; read {got!r}"


def _assert_switches(ddb, table: str, *, on: bool) -> None:
    """TTL stays on; PITR and contributor insights converge to `on`, each read from DynamoDB."""
    want = "ENABLED" if on else "DISABLED"
    ttl = _poll(lambda: ddb.describe_time_to_live(TableName=table)["TimeToLiveDescription"],
                lambda d: d.get("TimeToLiveStatus") in ("ENABLED", "DISABLED"),
                timeout_s=_SETTLE_S, interval_s=5, description=f"TTL on {table} settles")
    assert ttl == {"TimeToLiveStatus": "ENABLED", "AttributeName": _TTL_ATTRIBUTE}, (
        f"TTL is declared enabled on {_TTL_ATTRIBUTE!r} throughout; DescribeTimeToLive says {ttl!r}")
    pitr = _poll(lambda: ddb.describe_continuous_backups(TableName=table)[
        "ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"]["PointInTimeRecoveryStatus"],
        lambda s: s in ("ENABLED", "DISABLED"), timeout_s=_SETTLE_S, interval_s=5,
        description=f"PITR on {table} settles")
    assert pitr == want, f"PointInTimeRecoveryStatus is {pitr!r}, expected {want}"
    insights = _poll(lambda: ddb.describe_contributor_insights(TableName=table)[
        "ContributorInsightsStatus"], lambda s: s in ("ENABLED", "DISABLED"), timeout_s=_SETTLE_S,
        interval_s=5, description=f"contributor insights on {table} settle")
    assert insights == want, f"ContributorInsightsStatus is {insights!r}, expected {want}"


def _template(table: str, *, on: bool) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Table": {"Type": "AWS::DynamoDB::Table", "Properties": {
            "TableName": table,
            "BillingMode": "PAY_PER_REQUEST",
            "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"},
                                     {"AttributeName": "gk", "AttributeType": "S"}],
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
            "GlobalSecondaryIndexes": [{"IndexName": "byGk",
                                        "KeySchema": [{"AttributeName": "gk", "KeyType": "HASH"}],
                                        "Projection": {"ProjectionType": "KEYS_ONLY"}}],
            "SSESpecification": {"SSEEnabled": on},
            "TimeToLiveSpecification": {"AttributeName": _TTL_ATTRIBUTE, "Enabled": True},
            "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": on},
            "ContributorInsightsSpecification": {"Enabled": on},
            "TableClass": _TABLE_CLASS,
            "Tags": [{"Key": "sim2real", "Value": CHECK}],
        }}},
    })


STACK_TIMEOUT_S = 780.0
TEARDOWN_TIMEOUT_S = 600.0
_CREATE_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
_UPDATE_TERMINAL = {"UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE",
                    "UPDATE_ROLLBACK_FAILED"}


def _poll_stack(cfn, stack_id: str, terminal: set) -> dict:
    """Poll DescribeStacks until the stack reaches one of `terminal`; raise on timeout."""
    deadline = time.monotonic() + STACK_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if last["StackStatus"] in terminal:
            return last
        time.sleep(5.0)
    raise AssertionError(
        f"stack did not reach any of {sorted(terminal)!r} within {STACK_TIMEOUT_S}s "
        f"(last={last and last['StackStatus']!r})")


def _poll(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    """Poll probe() until predicate(result); raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last result: {last!r}")


def _outputs(stack: dict) -> dict:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _events(cfn, stack_id: str) -> list:
    """Every stack event, oldest first."""
    events = [e for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id)
              for e in page["StackEvents"]]
    return list(reversed(events))


def _physical_id(cfn, stack_id: str, logical: str) -> str:
    resources = [r for page in cfn.get_paginator("list_stack_resources").paginate(
        StackName=stack_id) for r in page["StackResourceSummaries"]]
    match = [r["PhysicalResourceId"] for r in resources if r["LogicalResourceId"] == logical]
    assert len(match) == 1, f"the stack must own exactly one {logical}; it lists {resources!r}"
    return match[0]


def _delete_stack_and_wait(cfn, stack_id: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; anything else raises."""
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + TEARDOWN_TIMEOUT_S
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            break
        time.sleep(5.0)
    raise RuntimeError(f"stack did not delete (last status {status!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
