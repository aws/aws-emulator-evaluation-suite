"""op-delete-stored-query-nonexistent."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _not_found_message(name):
    return f"The query '{name}' provided in the request is invalid. Please check the query name."


def _delete_query_quiet(cfg, name):
    try:
        cfg.delete_stored_query(QueryName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


CHECK = "op-delete-stored-query-nonexistent"
GROUP = "overly-permissive"
SERVICES = ["config"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After a stored query is deleted, GetStoredQuery and a second DeleteStoredQuery fail with
    ResourceNotFoundException and its exact message, as does DeleteStoredQuery for a name never created."""
    cfg = ctx.client("config")

    # Positive control: a real stored query round-trips through an
    # independent read, and DeleteStoredQuery genuinely removes it -- so the
    # not-found path below runs against a target that can actually
    # create/delete stored queries, not one that rejects everything.
    query_name = ctx.unique_name("sim2real-behav-cfg-absent-query-")
    cfg.put_stored_query(
        StoredQuery={
            "QueryName": query_name,
            "Description": "behavioral fidelity check",
            "Expression": "SELECT resourceId WHERE resourceType = 'AWS::S3::Bucket'",
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda a=query_name: _delete_query_quiet(cfg, a))

    fetched = cfg.get_stored_query(QueryName=query_name)["StoredQuery"]
    assert fetched["QueryName"] == query_name, (
        f"expected the just-created query to round-trip via an independent GetStoredQuery, got {fetched!r}"
    )

    cfg.delete_stored_query(QueryName=query_name)
    code, message = _error(lambda: cfg.get_stored_query(QueryName=query_name))
    assert code == "ResourceNotFoundException", (
        f"expected GetStoredQuery to report ResourceNotFoundException right after DeleteStoredQuery, got {code!r}"
    )
    assert message == _not_found_message(query_name), message

    # The contract under test: DeleteStoredQuery on that
    # already-gone name must itself report not-found rather than silently
    # succeeding a second time (double-delete).
    code, message = _error(lambda: cfg.delete_stored_query(QueryName=query_name))
    assert code == "ResourceNotFoundException", (
        f"expected a second DeleteStoredQuery on an already-deleted query to report ResourceNotFoundException, got {code!r}"
    )
    assert message == _not_found_message(query_name), message

    # And for a name that was never created in the first place.
    never_created = ctx.unique_name("sim2real-behav-cfg-absent-query-")
    code, message = _error(lambda: cfg.delete_stored_query(QueryName=never_created))
    assert code == "ResourceNotFoundException", (
        f"expected DeleteStoredQuery on a never-created query name to report ResourceNotFoundException, got {code!r}"
    )
    assert message == _not_found_message(never_created), message


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
