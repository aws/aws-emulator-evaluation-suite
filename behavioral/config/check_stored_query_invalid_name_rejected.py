"""stored-query-invalid-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "stored-query-invalid-name-rejected"
GROUP = "representation"
SERVICES = ["config"]


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected rejection, but call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutStoredQuery rejects a QueryName containing characters outside
    [a-zA-Z0-9-_] with ValidationException, the query is never created, and a
    valid name in the same call shape still succeeds (positive control)."""
    cfg = ctx.client("config")
    invalid_name = ctx.unique_name("sim2real invalid name ").replace("_", "-")

    code, message = _error(
        lambda: cfg.put_stored_query(
            StoredQuery={
                "QueryName": invalid_name,
                "Expression": "SELECT resourceId WHERE resourceType = 'AWS::S3::Bucket'",
            }
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        f"1 validation error detected: Value '{invalid_name}' at 'QueryName' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: ^[a-zA-Z0-9-_]+$"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the rejected query must not have been created under any name.
    all_names = {
        q["QueryName"] for q in cfg.list_stored_queries().get("StoredQueryMetadata", [])
    }
    assert invalid_name not in all_names, (
        f"rejected query {invalid_name!r} must not appear in ListStoredQueries, got {all_names!r}"
    )

    # Positive control: a valid name in the same shape succeeds.
    valid_name = ctx.unique_name("sim2real-validquery-").replace("_", "-")
    cfg.put_stored_query(
        StoredQuery={
            "QueryName": valid_name,
            "Expression": "SELECT resourceId WHERE resourceType = 'AWS::S3::Bucket'",
        }
    )
    ctx.on_cleanup(lambda: cfg.delete_stored_query(QueryName=valid_name))
    got = cfg.get_stored_query(QueryName=valid_name)["StoredQuery"]
    assert got["QueryName"] == valid_name, (
        f"expected positive-control query {valid_name!r}, got {got['QueryName']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
