"""stored-query-unicode-and-emoji-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

from botocore.exceptions import ClientError


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, call succeeded with {result!r}")


CHECK = "stored-query-unicode-and-emoji-round-trip"
GROUP = "representation"
SERVICES = ["config"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A stored query with unicode/emoji text in its expression and description
    is returned byte-identical by GetStoredQuery (no normalization/truncation),
    and is fully gone from GetStoredQuery once deleted."""
    cfg = ctx.client("config")
    query_name = ctx.unique_name("sim2real-storedquery-").replace("_", "-")

    expression = (
        "SELECT resourceId, resourceType "
        "WHERE resourceType = 'AWS::S3::Bucket' "
        "-- \u00e9\u00e8\u00ea\u00eb \u4e2d\u6587\u6d4b\u8bd5 \U0001F600\U0001F680\U0001F389 "
        "\u0645\u0631\u062d\u0628\u0627 \u0e2a\u0e27\u0e31\u0e2a\u0e14\u0e35"
    )
    description = "unicode test \u00fc\u00f1\u00ee\u00e7\u00f8\u00de \U0001F98A\U0001F30D description"

    resp = cfg.put_stored_query(
        StoredQuery={
            "QueryName": query_name,
            "Description": description,
            "Expression": expression,
        },
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    query_arn = resp["QueryArn"]
    deleted = []
    ctx.on_cleanup(lambda: None if deleted else cfg.delete_stored_query(QueryName=query_name))

    got = cfg.get_stored_query(QueryName=query_name)["StoredQuery"]

    assert got["QueryName"] == query_name, (
        f"query name not round-tripped: {got['QueryName']!r} != {query_name!r}"
    )
    assert got["Expression"] == expression, (
        f"expression not byte-identical: {got['Expression']!r} != {expression!r}"
    )
    assert got["Description"] == description, (
        f"description not byte-identical: {got['Description']!r} != {description!r}"
    )
    assert got["QueryArn"] == query_arn, (
        f"query arn changed between put and get: {got['QueryArn']!r} != {query_arn!r}"
    )

    cfg.delete_stored_query(QueryName=query_name)
    deleted.append(query_name)
    code, message = _error(lambda: cfg.get_stored_query(QueryName=query_name))
    assert code == "ResourceNotFoundException", (
        f"deleted stored query still readable, or wrong error code: {code!r}"
    )
    expected_message = (
        f"The query '{query_name}' provided in the request is invalid. "
        "Please check the query name."
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
