"""stored-query-lifecycle."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected rejection but call succeeded with {result!r}")

CHECK = "stored-query-lifecycle"
GROUP = 'stored-query'
SERVICES = ['config']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutStoredQuery rejects malformed query expressions, otherwise the
    stored query round-trips through GetStoredQuery and is fully removed by
    DeleteStoredQuery."""
    cfg = ctx.client("config")
    query_name = ctx.unique_name("sim2real-behav-cfg-query-")
    expression = "SELECT resourceId, resourceType WHERE resourceType = 'AWS::S3::Bucket'"

    bad_query_name = ctx.unique_name("sim2real-behav-cfg-badquery-")
    code, message = _error(
        lambda: cfg.put_stored_query(
            StoredQuery={
                "QueryName": bad_query_name,
                "Expression": "NOT VALID CONFIG SQL ((()",
            }
        )
    )
    assert code == "ValidationException", code
    assert message == "syntax error at line 1, column 1", message

    # Effect absent: the rejected query must not have been created under any name.
    all_names = {
        q["QueryName"] for q in cfg.list_stored_queries().get("StoredQueryMetadata", [])
    }
    assert bad_query_name not in all_names, all_names

    cfg.put_stored_query(
        StoredQuery={
            "QueryName": query_name,
            "Description": "behavioral fidelity check",
            "Expression": expression,
        }
    )
    deleted = []
    ctx.on_cleanup(
        lambda a=query_name: None if deleted else cfg.delete_stored_query(QueryName=a)
    )

    fetched = cfg.get_stored_query(QueryName=query_name)["StoredQuery"]
    assert fetched["QueryName"] == query_name, fetched
    assert fetched["Expression"] == expression, fetched

    cfg.delete_stored_query(QueryName=query_name)
    deleted.append(query_name)
    code, message = _error(lambda: cfg.get_stored_query(QueryName=query_name))
    assert code == "ResourceNotFoundException", code
    expected_message = (
        f"The query '{query_name}' provided in the request is invalid. "
        "Please check the query name."
    )
    assert message == expected_message, message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
