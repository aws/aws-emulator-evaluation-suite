"""list-tags-of-resource-arn-wrong-json-type-rejected."""
from __future__ import annotations

import json
import time

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = 'list-tags-of-resource-arn-wrong-json-type-rejected'
GROUP = 'tag-api-type-validation'
SERVICES = ['dynamodb']

_SER = 'com.amazon.coral.service#SerializationException'


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _await_table_active(ctx, ddb, table: str) -> None:
    """Poll DescribeTable every second until the table is ACTIVE, bounded by the budget."""
    deadline = time.time() + _budget_s(ctx, 300.0)
    while True:
        status = ddb.describe_table(TableName=table)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return
        if time.time() >= deadline and _budget_spent(ctx):
            raise TimeoutError(f"table {table!r} ACTIVE: the run budget ended first; not graded")
        assert time.time() < deadline, f"table {table!r} never reached ACTIVE (last {status!r})"
        time.sleep(1.0)


def _teardown(undo, *not_found: str):
    """A cleanup running undo(); only the named not-found codes mean it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _teardown_table(ctx, ddb, table: str) -> None:
    """Delete a table, bounded-retrying only DynamoDB's own tags-still-updating refusal."""
    deadline = time.time() + _budget_s(ctx, 60.0)
    while True:
        try:
            ddb.delete_table(TableName=table)
            return
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ResourceNotFoundException":
                return
            if err["Code"] == "ResourceInUseException" and "tags are being updated" in err["Message"]:
                assert time.time() < deadline, f"table {table!r} tags never settled: {err!r}"
                time.sleep(2.0)
                continue
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation",
      "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """ListTagsOfResource refuses a ResourceArn sent as a non-string JSON value with
    SerializationException, leaving a table's existing tags unchanged.
    """
    import urllib3

    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ltrtype-t-")

    ddb.create_table(
        TableName=table, BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _teardown_table(ctx, ddb, table))
    _await_table_active(ctx, ddb, table)
    table_arn = ddb.describe_table(TableName=table)["Table"]["TableArn"]

    expected_tags = {("sim2real", CHECK), ("env", "test")}

    def _tag_set(tags_list):
        return {(t["Key"], t["Value"]) for t in tags_list}

    ddb.tag_resource(ResourceArn=table_arn, Tags=[{"Key": "env", "Value": "test"}])
    control_tags = []
    deadline = time.time() + _budget_s(ctx, 60.0)
    while True:
        control_tags = ddb.list_tags_of_resource(ResourceArn=table_arn).get("Tags", [])
        if _tag_set(control_tags) == expected_tags or time.time() >= deadline:
            break
        time.sleep(2.0)
    assert _tag_set(control_tags) == expected_tags, (
        f"ListTagsOfResource did not read back the tag TagResource wrote: {control_tags!r}")

    raw_creds = ddb._request_signer._credentials
    frozen = (raw_creds.get_frozen_credentials()
              if hasattr(raw_creds, "get_frozen_credentials") else raw_creds)
    endpoint = ddb.meta.endpoint_url
    verify = ctx.http_verify
    pool = urllib3.PoolManager(cert_reqs="CERT_REQUIRED" if verify else "CERT_NONE",
                               ca_certs=verify if isinstance(verify, str) else None)

    def raw(body: dict):
        data = json.dumps(body).encode()
        req = AWSRequest(method="POST", url=endpoint, data=data, headers={
            "content-type": "application/x-amz-json-1.0",
            "x-amz-target": "DynamoDB_20120810.ListTagsOfResource"})
        SigV4Auth(frozen, "dynamodb", ctx.region).add_auth(req)
        sent = dict(req.headers.items())
        resp = pool.request("POST", endpoint, body=data, headers=sent, retries=False)
        return resp.status, json.loads(resp.data) if resp.data else {}

    # ---- 1. positive control over the same raw transport: a well-typed ResourceArn succeeds.
    status, body = raw({"ResourceArn": table_arn})
    assert status == 200, f"a well-typed ResourceArn over raw HTTP gave {status!r}: {body!r}"
    assert _tag_set(body.get("Tags", [])) == expected_tags, (
        f"the raw request's Tags were {body.get('Tags')!r}, expected {sorted(expected_tags)!r}")

    # ---- 2. ResourceArn sent as a JSON number instead of a string.
    status, body = raw({"ResourceArn": 123456789012})
    assert status == 400, f"a numeric ResourceArn gave status {status!r}: {body!r}"
    assert body.get("__type") == _SER, (
        f"a numeric ResourceArn gave __type {body.get('__type')!r}, expected {_SER!r}")
    assert body.get("Message") == "NUMBER_VALUE cannot be converted to String", (
        f"a numeric ResourceArn gave message {body.get('Message')!r}")

    # ---- 3. ResourceArn sent as a JSON array instead of a string; this one carries no message.
    status, body = raw({"ResourceArn": [table_arn]})
    assert status == 400, f"a list-typed ResourceArn gave status {status!r}: {body!r}"
    assert body.get("__type") == _SER, (
        f"a list-typed ResourceArn gave __type {body.get('__type')!r}, expected {_SER!r}")
    assert body == {"__type": _SER}, (
        f"a list-typed ResourceArn gave body {body!r}, expected only __type with no message")

    # ---- 4. effect-absent: neither refused call changed the table's real tags.
    after = ddb.list_tags_of_resource(ResourceArn=table_arn)["Tags"]
    assert _tag_set(after) == expected_tags, (
        f"ListTagsOfResource after the refusals returned {after!r}, expected the unaffected "
        f"{sorted(expected_tags)!r}")

    ddb.untag_resource(ResourceArn=table_arn, TagKeys=["env"])
    settled_tags = []
    deadline = time.time() + _budget_s(ctx, 60.0)
    while True:
        settled_tags = ddb.list_tags_of_resource(ResourceArn=table_arn).get("Tags", [])
        if _tag_set(settled_tags) == {("sim2real", CHECK)} or time.time() >= deadline:
            break
        time.sleep(2.0)
    assert _tag_set(settled_tags) == {("sim2real", CHECK)}, (
        f"UntagResource did not settle before delete: {settled_tags!r}")

    _teardown_table(ctx, ddb, table)
    deadline = time.time() + _budget_s(ctx, 300.0)
    gone = None
    while time.time() < deadline:
        try:
            ddb.describe_table(TableName=table)
        except ClientError as exc:
            gone = exc.response.get("Error", {}).get("Code")
            break
        time.sleep(2.0)
    if gone is None and _budget_spent(ctx):
        raise TimeoutError(f"table {table!r} deleted: the run budget ended first; not graded")
    assert gone == "ResourceNotFoundException", (
        f"the table was still describable after delete_table (code {gone!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
