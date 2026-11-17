"""put-item-list-holding-string-set-two-empty-string-members-rejected-as-duplicate."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-item-list-holding-string-set-two-empty-string-members-rejected-as-duplicate"
GROUP = "representation"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"
_INVALID = "1 validation error detected: One or more parameter values were invalid: "
_SS_DUPLICATE = (ERR_VALIDATION, _INVALID + 'Input collection ["", ""] contains duplicates.')


def _error(fn):
    """(code, message) of the ClientError fn() raises; raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code!r}, got {got_code!r} ({got_message!r})"
    assert got_message == message, f"unexpected message {got_message!r}"


@tags("axis:rejection", "cap:c2", "concern:representation", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """PutItem refuses an L element holding a string set with two empty-string members
    as a duplicate collection, and stores nothing; a legal two-member nested SS round-trips.
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-ddb-lssdup-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # Positive control: a legal two-member SS nested in an L round-trips.
    ddb.put_item(TableName=t, Item={"pk": {"S": "ok"}, "attr": {"L": [{"SS": ["", "x"]}]}})
    got = ddb.get_item(TableName=t, Key={"pk": {"S": "ok"}}, ConsistentRead=True).get("Item")
    assert got is not None, "a legal two-member SS nested in an L must be stored"
    assert sorted(got["attr"]["L"][0]["SS"]) == ["", "x"], (
        f"a legal two-member SS nested in an L must round-trip both members, got {got['attr']!r}"
    )

    item = {"pk": {"S": "dup"}, "attr": {"L": [{"SS": ["", ""]}]}}
    expect_error(lambda: ddb.put_item(TableName=t, Item=item), *_SS_DUPLICATE)
    assert ddb.get_item(TableName=t, Key={"pk": {"S": "dup"}}, ConsistentRead=True).get("Item") is None, (
        "a rejected duplicate-member SS nested in an L must not be stored"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
