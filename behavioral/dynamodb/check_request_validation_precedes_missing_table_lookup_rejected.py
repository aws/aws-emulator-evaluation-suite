"""request-validation-precedes-missing-table-lookup-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "request-validation-precedes-missing-table-lookup-rejected"
GROUP = "validation"
SERVICES = ["dynamodb"]

_NOT_FOUND = ("ResourceNotFoundException", "Requested resource not found")
_EXPECTED_EQ_NO_VALUE_MESSAGE = (
    "1 validation error detected: One or more parameter values were invalid: "
    "Value or AttributeValueList must be used with ComparisonOperator: EQ for Attribute: a"
)
_PROJECTION_EMPTY_MESSAGE = "Invalid ProjectionExpression: The expression can not be empty;"
_PROJECTION_SYNTAX_MESSAGE = 'Invalid ProjectionExpression: Syntax error; token: ".", near: "..b"'
_PROJECTION_OVERLAP_MESSAGE = (
    "Invalid ProjectionExpression: Two document paths overlap with each other; "
    "must remove or rewrite one of these paths; path one: [a], path two: [a, b]"
)
_UPDATE_EMPTY_MESSAGE = "1 validation error detected: Invalid UpdateExpression: The expression can not be empty;"
_UPDATE_SYNTAX_MESSAGE = '1 validation error detected: Invalid UpdateExpression: Syntax error; token: "<EOF>", near: "SET"'
_UPDATE_RESERVED_MESSAGE = (
    "1 validation error detected: Invalid UpdateExpression: Attribute name is a reserved keyword; "
    "reserved keyword: status"
)
_UPDATE_UNDEFINED_NAME_MESSAGE = (
    "1 validation error detected: Invalid UpdateExpression: An expression attribute name used in "
    "the document path is not defined; attribute name: #x"
)
_FILTER_SYNTAX_MESSAGE = 'Invalid FilterExpression: Syntax error; token: "+", near: "a +"'
_BATCH_DUPLICATE_KEYS_MESSAGE = "Provided list of item keys contains duplicates"


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """On a table that does not exist, malformed Expected, projection, update, filter and duplicate
    batch keys are ValidationException, while the same requests well formed are ResourceNotFound.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Programming.Errors.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-absent-")
    key = {"pk": {"S": "k"}}

    def check(label, fn, want):
        code, msg = _error(fn)
        assert (code, msg) == want, f"{label} on the missing table gave {code!r}: {msg!r}, expected {want!r}"

    no_value = {"a": {"ComparisonOperator": "EQ"}}
    one_value = {"a": {"ComparisonOperator": "EQ", "AttributeValueList": [{"S": "x"}]}}
    check("PutItem with Expected EQ and no value",
          lambda: ddb.put_item(TableName=table, Item=key, Expected=no_value),
          ("ValidationException", _EXPECTED_EQ_NO_VALUE_MESSAGE))
    check("PutItem with Expected EQ and one value",
          lambda: ddb.put_item(TableName=table, Item=key, Expected=one_value), _NOT_FOUND)
    check("DeleteItem with Expected EQ and no value",
          lambda: ddb.delete_item(TableName=table, Key=key, Expected=no_value),
          ("ValidationException", _EXPECTED_EQ_NO_VALUE_MESSAGE))
    check("DeleteItem with Expected EQ and one value",
          lambda: ddb.delete_item(TableName=table, Key=key, Expected=one_value), _NOT_FOUND)

    for projection, message in (
        ("", _PROJECTION_EMPTY_MESSAGE),
        ("a..b", _PROJECTION_SYNTAX_MESSAGE),
        ("a, a.b", _PROJECTION_OVERLAP_MESSAGE),
    ):
        check(f"GetItem with ProjectionExpression {projection!r}",
              lambda p=projection: ddb.get_item(TableName=table, Key=key, ProjectionExpression=p),
              ("ValidationException", message))
    check("GetItem with ProjectionExpression 'a, b'",
          lambda: ddb.get_item(TableName=table, Key=key, ProjectionExpression="a, b"), _NOT_FOUND)

    value = {":v": {"S": "x"}}
    for expression, message in (
        ("", _UPDATE_EMPTY_MESSAGE),
        ("SET", _UPDATE_SYNTAX_MESSAGE),
        ("SET status = :v", _UPDATE_RESERVED_MESSAGE),
        ("SET #x = :v", _UPDATE_UNDEFINED_NAME_MESSAGE),
    ):
        extra = {} if expression in ("", "SET") else {"ExpressionAttributeValues": value}
        check(f"UpdateItem with UpdateExpression {expression!r}",
              lambda e=expression, x=extra: ddb.update_item(TableName=table, Key=key, UpdateExpression=e, **x),
              ("ValidationException", message))
    check("UpdateItem with UpdateExpression 'SET #s = :v'",
          lambda: ddb.update_item(TableName=table, Key=key, UpdateExpression="SET #s = :v",
                                  ExpressionAttributeNames={"#s": "status"}, ExpressionAttributeValues=value),
          _NOT_FOUND)

    check("Scan with FilterExpression 'a +'",
          lambda: ddb.scan(TableName=table, FilterExpression="a +"),
          ("ValidationException", _FILTER_SYNTAX_MESSAGE))
    check("Scan with FilterExpression 'attribute_exists(a)'",
          lambda: ddb.scan(TableName=table, FilterExpression="attribute_exists(a)"), _NOT_FOUND)

    check("BatchGetItem with a duplicated key",
          lambda: ddb.batch_get_item(RequestItems={table: {"Keys": [key, key]}}),
          ("ValidationException", _BATCH_DUPLICATE_KEYS_MESSAGE))
    check("BatchGetItem with distinct keys",
          lambda: ddb.batch_get_item(RequestItems={table: {"Keys": [key, {"pk": {"S": "k2"}}]}}), _NOT_FOUND)

    code, msg = _error(lambda: ddb.describe_table(TableName=table))
    want = ("ResourceNotFoundException", f"Requested resource not found: Table: {table} not found")
    assert (code, msg) == want, f"after the requests the table {table} describes as {code!r}: {msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
