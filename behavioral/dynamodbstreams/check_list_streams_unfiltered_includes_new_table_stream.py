"""list-streams-unfiltered-includes-new-table-stream."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-streams-unfiltered-includes-new-table-stream"
GROUP = "listing"
SERVICES = ["dynamodbstreams"]


def _find_unfiltered(streams, stream_arn: str, *, timeout_s: float = 90.0,
                      page_limit: int = 100, max_pages: int = 500):
    """The ListStreams entry for ``stream_arn``, found with no TableName filter.

    Walks every page via ExclusiveStartStreamArn/LastEvaluatedStreamArn; retried over a bounded
    window because other tables' streams can be created or deleted between pages.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        start = None
        for _page in range(max_pages):
            kwargs = {"Limit": page_limit}
            if start is not None:
                kwargs["ExclusiveStartStreamArn"] = start
            resp = streams.list_streams(**kwargs)
            for entry in resp.get("Streams", []):
                if entry["StreamArn"] == stream_arn:
                    return entry
            start = resp.get("LastEvaluatedStreamArn")
            if start is None:
                break
        if time.monotonic() >= deadline:
            return None
        time.sleep(2.0)


@tags("axis:happy-path", "cap:c2", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListStreams with no TableName lists the account's streams; paging with
    ExclusiveStartStreamArn surfaces an entry whose StreamArn matches DescribeTable's
    LatestStreamArn and names the new table.
    """
    ddb = ctx.client("dynamodb")
    streams = ctx.client("dynamodbstreams")

    table = ctx.unique_name("sim2real-behav-lsunf-")
    created = ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        StreamSpecification={"StreamEnabled": True, "StreamViewType": "KEYS_ONLY"},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(
        TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    described = ddb.describe_table(TableName=table)["Table"]
    stream_arn = described["LatestStreamArn"]
    label = described["LatestStreamLabel"]
    want_arn = f"{described['TableArn']}/stream/{label}"
    assert stream_arn == want_arn, (
        f"DescribeTable LatestStreamArn is {stream_arn!r}, expected {want_arn!r}"
    )

    entry = _find_unfiltered(streams, stream_arn)
    assert entry is not None, (
        f"an unfiltered ListStreams must, across its pages, surface an entry for {stream_arn!r}"
    )
    assert entry["TableName"] == table, (
        f"the ListStreams entry for {stream_arn!r} must name the table, got {entry!r}"
    )
    assert entry["StreamLabel"] == label, (
        f"the entry's StreamLabel must be DescribeTable's LatestStreamLabel {label!r}, got {entry!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
