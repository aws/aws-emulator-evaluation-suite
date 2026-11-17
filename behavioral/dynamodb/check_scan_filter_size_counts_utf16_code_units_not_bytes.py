"""scan-filter-size-counts-utf16-code-units-not-bytes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "scan-filter-size-counts-utf16-code-units-not-bytes"
GROUP = "scan"
SERVICES = ["dynamodb"]

#: pk -> (string value, its UTF-16 code unit count). "bmp" is 3 multi-byte BMP characters (7
#: UTF-8 bytes, 3 code units); "astral" is one single code point outside the BMP, which UTF-16
#: represents as a surrogate pair (4 UTF-8 bytes, 1 code point, 2 code units); "ascii2" is a
#: plain two-character string that lands on the same code-unit count as "astral" so a filter
#: that matched on byte or code-point count instead of code units would pick the wrong row.
_BMP = "éα中"
_ASTRAL = "\U0001f600"
_ROWS = {
    "bmp": _BMP,
    "astral": _ASTRAL,
    "ascii2": "hi",
}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Scan FilterExpression's size() on a String counts UTF-16 code units, so a surrogate-pair
    character counts as 2 even though it is one code point and 4 UTF-8 bytes.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbu16-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    for pk, value in _ROWS.items():
        ddb.put_item(TableName=table, Item={"pk": {"S": pk}, "s": {"S": value}})

    def scan_pks(expr: str, values: dict) -> set:
        resp = ddb.scan(
            TableName=table, ConsistentRead=True,
            FilterExpression=expr, ExpressionAttributeValues=values,
        )
        return {i["pk"]["S"] for i in resp["Items"]}

    three = scan_pks("size(s) = :n", {":n": {"N": "3"}})
    assert three == {"bmp"}, f"size(s) = 3 selected {sorted(three)!r}, expected ['bmp']"

    two = scan_pks("size(s) = :n", {":n": {"N": "2"}})
    assert two == {"astral", "ascii2"}, (
        f"size(s) = 2 selected {sorted(two)!r}, expected ['ascii2', 'astral'] "
        "(the astral character's UTF-16 surrogate pair, same count as the two-character string)"
    )

    # Neither the 7 UTF-8 bytes of "bmp" nor the single code point of "astral" is what size()
    # reports: both comparisons below select nothing.
    seven = scan_pks("size(s) = :n", {":n": {"N": "7"}})
    assert seven == set(), f"size(s) = 7 selected {sorted(seven)!r}, expected none (not UTF-8 bytes)"

    one = scan_pks("size(s) = :n", {":n": {"N": "1"}})
    assert one == set(), f"size(s) = 1 selected {sorted(one)!r}, expected none (not code points)"

    # Positive control: comparing the attribute directly (no size()) still finds the row,
    # proving the table and ExpressionAttributeValues plumbing work on their own.
    control = scan_pks("s = :v", {":v": {"S": _BMP}})
    assert control == {"bmp"}, f"s = <the bmp string> selected {sorted(control)!r}, expected ['bmp']"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
