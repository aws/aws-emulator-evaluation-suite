"""put-query-definition-then-describe."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-query-definition-then-describe"
GROUP = 'query-definitions'
SERVICES = ['logs']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutQueryDefinition makes the definition visible via DescribeQueryDefinitions."""
    svc = ctx.client("logs")
    qd_name = ctx.unique_name("sim2real-behav-qd-")
    resp = svc.put_query_definition(
        name=qd_name,
        queryString="fields @timestamp, @message | limit 20",
    )
    qd_id = resp["queryDefinitionId"]
    ctx.on_cleanup(lambda _i=qd_id: svc.delete_query_definition(queryDefinitionId=_i))

    described = svc.describe_query_definitions(queryDefinitionNamePrefix=qd_name)
    found = {q["queryDefinitionId"]: q for q in described.get("queryDefinitions", [])}
    assert qd_id in found, f"expected {qd_id} in {list(found)}"
    assert found[qd_id]["name"] == qd_name, found[qd_id]
    assert found[qd_id]["queryString"] == "fields @timestamp, @message | limit 20", (
        f"expected the submitted queryString to round-trip, got {found[qd_id]!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
