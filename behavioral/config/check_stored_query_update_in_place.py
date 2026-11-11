"""stored-query-update-in-place."""

from __future__ import annotations

from behavioral_harness import tags


CHECK = "stored-query-update-in-place"
GROUP = 'stored-query'
SERVICES = ['config']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutStoredQuery on an existing QueryName updates it in place: the QueryId
    is stable, the expression/description are replaced, and ListStoredQueries
    shows exactly one entry for the name."""
    cfg = ctx.client("config")
    query_name = ctx.unique_name("sim2real-behav-cfg-query-")
    cfg.put_stored_query(
        StoredQuery={
            "QueryName": query_name,
            "Description": "first version",
            "Expression": "SELECT resourceId WHERE resourceType = 'AWS::S3::Bucket'",
        },
        Tags=[{"Key": "env", "Value": "test"}, {"Key": "owner", "Value": "fidelity"}],
    )
    ctx.on_cleanup(lambda a=query_name: cfg.delete_stored_query(QueryName=a))

    first = cfg.get_stored_query(QueryName=query_name)["StoredQuery"]
    query_id = first["QueryId"]
    assert first["Description"] == "first version", first

    new_expression = "SELECT resourceId WHERE resourceType = 'AWS::EC2::Volume'"
    cfg.put_stored_query(
        StoredQuery={
            "QueryName": query_name,
            "Description": "second version",
            "Expression": new_expression,
        }
    )

    updated = cfg.get_stored_query(QueryName=query_name)["StoredQuery"]
    assert updated["QueryId"] == query_id, (first, updated)
    assert updated["Description"] == "second version", updated
    assert updated["Expression"] == new_expression, updated

    matching = [
        q
        for q in cfg.list_stored_queries()["StoredQueryMetadata"]
        if q["QueryName"] == query_name
    ]
    assert len(matching) == 1, matching
    assert matching[0]["QueryId"] == query_id, matching


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
