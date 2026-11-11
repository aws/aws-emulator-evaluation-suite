"""list-stored-queries-pagination-completeness."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-stored-queries-pagination-completeness"
GROUP = "data-plane"
SERVICES = ["config"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paginating ListStoredQueries with a small MaxResults and following NextToken returns
    the complete, non-duplicated set of stored queries created via PutStoredQuery.
    """
    cfg = ctx.client("config")

    created_names = []
    for i in range(5):
        name = ctx.unique_name(f"sim2realsq{i}-")
        expression = (
            "SELECT resourceId, resourceType WHERE resourceType = 'AWS::EC2::Instance' "
            f"AND resourceId = '{name}'"
        )
        cfg.put_stored_query(
            StoredQuery={
                "QueryName": name,
                "Description": "sim2real pagination completeness check",
                "Expression": expression,
            },
            Tags=[{"Key": "env", "Value": "test"}, {"Key": "owner", "Value": "fidelity"}],
        )
        created_names.append(name)
        ctx.on_cleanup(lambda n=name: cfg.delete_stored_query(QueryName=n))

    seen_names = []
    next_token = None
    for _ in range(100):
        kwargs = {"MaxResults": 2}
        if next_token:
            kwargs["NextToken"] = next_token
        page = cfg.list_stored_queries(**kwargs)
        seen_names.extend(m["QueryName"] for m in page.get("StoredQueryMetadata", []))
        next_token = page.get("NextToken")
        if not next_token:
            break
    else:
        raise AssertionError("ListStoredQueries pagination did not terminate within 100 pages")

    seen_created = [n for n in seen_names if n in created_names]
    assert sorted(seen_created) == sorted(created_names), (
        f"expected exactly {sorted(created_names)}, got {sorted(seen_created)}"
    )
    assert len(seen_created) == len(set(seen_created)), "duplicate stored query returned across pages"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
