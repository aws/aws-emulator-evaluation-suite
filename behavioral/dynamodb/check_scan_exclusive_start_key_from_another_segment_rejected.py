"""scan-exclusive-start-key-from-another-segment-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scan-exclusive-start-key-from-another-segment-rejected"
GROUP = "negative-classes"
SERVICES = ["dynamodb"]

_TOTAL_SEGMENTS = 2
_DONOR_SEGMENT = 0
_OTHER_SEGMENT = 1
_ITEM_COUNT = 60


def _error_code(fn) -> tuple[str, str]:
    """The (code, message) ``fn`` raises. An unexpected success raises too, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A parallel Scan's ExclusiveStartKey must pair with the Segment it was returned under;
    resuming it under a different Segment of the same TotalSegments is refused.
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=t,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    items = [{"pk": {"S": f"item-{i:03d}"}} for i in range(_ITEM_COUNT)]
    for start in range(0, len(items), 25):
        batch = items[start:start + 25]
        resp = ddb.batch_write_item(
            RequestItems={t: [{"PutRequest": {"Item": it}} for it in batch]}
        )
        assert resp["UnprocessedItems"] == {}, (
            f"BatchWriteItem left {resp['UnprocessedItems']!r} unprocessed while seeding"
        )

    # Positive control: every written item is visible to an unsegmented, consistent scan.
    whole = ddb.scan(TableName=t, Select="COUNT", ConsistentRead=True)
    assert whole["Count"] == _ITEM_COUNT, (
        f"an unsegmented Scan counted {whole['Count']!r}, expected the {_ITEM_COUNT!r} seeded items"
    )

    # The donor segment read whole, in one page: the reference for the Limit=1 page and its resume.
    donor_all = ddb.scan(TableName=t, Segment=_DONOR_SEGMENT, TotalSegments=_TOTAL_SEGMENTS,
                         ConsistentRead=True)
    assert "LastEvaluatedKey" not in donor_all, (
        f"segment {_DONOR_SEGMENT!r} of {_ITEM_COUNT} small items must fit on one page, got "
        f"LastEvaluatedKey {donor_all.get('LastEvaluatedKey')!r}"
    )
    donor_items = donor_all["Items"]

    donor_page = ddb.scan(TableName=t, Segment=_DONOR_SEGMENT, TotalSegments=_TOTAL_SEGMENTS,
                          Limit=1, ConsistentRead=True)
    assert donor_page["Items"] == donor_items[:1], (
        f"a Limit=1 Scan of segment {_DONOR_SEGMENT!r} returned {donor_page['Items']!r}, expected "
        f"the segment's first item {donor_items[:1]!r}"
    )
    lek = donor_page.get("LastEvaluatedKey")
    assert lek == donor_items[0], (
        f"the Limit=1 page's LastEvaluatedKey {lek!r} must name its own item {donor_items[0]!r}"
    )

    code, message = _error_code(lambda: ddb.scan(
        TableName=t, Segment=_OTHER_SEGMENT, TotalSegments=_TOTAL_SEGMENTS,
        ExclusiveStartKey=lek, ConsistentRead=True,
    ))
    expected_message = (
        "The provided starting key is invalid: Invalid ExclusiveStartKey. Please use "
        f"ExclusiveStartKey with correct Segment. TotalSegments: {_TOTAL_SEGMENTS} "
        f"Segment: {_OTHER_SEGMENT}"
    )
    assert (code, message) == ("ValidationException", expected_message), (
        f"resuming segment {_DONOR_SEGMENT!r}'s key under segment {_OTHER_SEGMENT!r} raised "
        f"{(code, message)!r}, expected {('ValidationException', expected_message)!r}"
    )

    # Positive control: the SAME key resumes cleanly under the segment it was returned under.
    resumed = ddb.scan(TableName=t, Segment=_DONOR_SEGMENT, TotalSegments=_TOTAL_SEGMENTS,
                       ExclusiveStartKey=lek, ConsistentRead=True)
    assert resumed["Items"] == donor_items[1:] and "LastEvaluatedKey" not in resumed, (
        f"resuming segment {_DONOR_SEGMENT!r}'s own key under its own segment must return the rest "
        f"of that segment {donor_items[1:]!r}, got {resumed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
