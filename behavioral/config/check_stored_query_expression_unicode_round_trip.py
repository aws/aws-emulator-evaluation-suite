"""stored-query-expression-unicode-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "stored-query-expression-unicode-round-trip"
GROUP = "representation"
SERVICES = ["config"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A stored query containing unicode characters and SQL-special characters is
    returned unchanged (byte-identical) by GetStoredQuery."""
    cfg = ctx.client("config")
    query_name = ctx.unique_name("sim2real-query-")
    description = "Sim2Real stored query — unicode 测试 café emoji 🚀 Ω δ β"
    expression = (
        "SELECT resourceId, resourceType, tags.value "
        "WHERE tags.value = 'unicode: héllo \"Wörld\" — 日本語 emoji 🎉 café résumé; "
        "50%wildcard_test -- sql comment; DROP TABLE x;' "
        "AND resourceType = 'AWS::S3::Bucket'"
    )

    put_resp = cfg.put_stored_query(
        StoredQuery={
            "QueryName": query_name,
            "Description": description,
            "Expression": expression,
        }
    )
    ctx.on_cleanup(lambda: cfg.delete_stored_query(QueryName=query_name))
    assert put_resp["QueryArn"], f"PutStoredQuery returned no QueryArn: {put_resp!r}"

    get_resp = cfg.get_stored_query(QueryName=query_name)
    stored = get_resp["StoredQuery"]
    assert stored["QueryName"] == query_name, (
        f"QueryName not round-tripped: expected {query_name!r}, got {stored['QueryName']!r}"
    )
    assert stored["Description"] == description, (
        f"Description not byte-identical: expected {description!r}, got {stored['Description']!r}"
    )
    assert stored["Expression"] == expression, (
        f"Expression not byte-identical: expected {expression!r}, got {stored['Expression']!r}"
    )
    assert stored["QueryArn"] == put_resp["QueryArn"], (
        f"QueryArn changed on read: expected {put_resp['QueryArn']!r}, got {stored['QueryArn']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
