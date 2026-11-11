"""stored-query-unicode-expression-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "stored-query-unicode-expression-round-trip"
GROUP = "representation"
SERVICES = ["config"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetStoredQuery returns a StoredQuery with a unicode Description and a large multi-line Expression
    unchanged, with its QueryName and QueryArn."""
    cfg = ctx.client("config")
    query_name = ctx.unique_name("sim2real-behav-query-")

    description = (
        "查询说明: 检测未启用版本控制的 S3 桶 — "
        "Ünïcödé descripción with emoji 😀🚀 and symbols ★Ω≈ç√∫˜µ≤≥÷ "
        '\u0000-free control text, quotes " and \' and backslash \\ end.'
    )
    # NOTE: unlike GetStoredQuery (which is a pure byte-preserving store/retrieve of the
    # Expression text), PutStoredQuery DOES validate the SQL-like Expression against the
    # advanced-query schema at write time -- a quoted identifier such as tags."日本語キー"
    # fails with "failed to locate identifier in query" because it isn't a recognized
    # field path. The unicode/representation payload is therefore carried in the plain
    # `tags` field selector plus string literals and a comment, not in an identifier name.
    expression = (
        "SELECT\n"
        "  resourceId,\n"
        "  resourceType,\n"
        "  tags,\n"
        "  supplementaryConfiguration.BucketVersioningConfiguration.status\n"
        "WHERE\n"
        "  resourceType = 'AWS::S3::Bucket'\n"
        "  AND supplementaryConfiguration.BucketVersioningConfiguration.status = 'Off'\n"
        "  -- unicode comment-like literal kept inside a string: 'ünïcödé Ω 😀'\n"
        "ORDER BY\n"
        "  resourceId\n"
    )

    put_resp = cfg.put_stored_query(
        StoredQuery={
            "QueryName": query_name,
            "Description": description,
            "Expression": expression,
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    query_arn = put_resp["QueryArn"]
    ctx.on_cleanup(lambda: cfg.delete_stored_query(QueryName=query_name))

    got = cfg.get_stored_query(QueryName=query_name)["StoredQuery"]
    assert got["QueryName"] == query_name, (
        f"expected QueryName {query_name!r}, got {got.get('QueryName')!r}"
    )
    assert got["Description"] == description, (
        f"description not byte-identical: expected {description!r}, got {got.get('Description')!r}"
    )
    assert got["Expression"] == expression, (
        f"expression not byte-identical: expected {expression!r}, got {got.get('Expression')!r}"
    )
    assert got["QueryArn"] == query_arn, (
        f"expected QueryArn {query_arn!r} on independent read, got {got.get('QueryArn')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
