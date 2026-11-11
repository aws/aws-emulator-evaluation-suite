"""schema-mapping-list-pagination-respects-max-results."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schema-mapping-list-pagination-respects-max-results"
GROUP = "state"
SERVICES = ["entityresolution"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSchemaMappings with maxResults=1 returns exactly one item plus a nextToken, and
    paging through nextToken eventually visits every schema mapping created by this check
    exactly once (no duplicates, no omissions)."""
    er = ctx.client("entityresolution")
    created_names = set()
    for i in range(3):
        name = ctx.unique_name(f"sim2real-er-page-{i}-")
        er.create_schema_mapping(
            schemaName=name,
            mappedInputFields=[
                {"fieldName": "id", "type": "UNIQUE_ID"},
                {"fieldName": "email", "type": "EMAIL_ADDRESS", "matchKey": "email"},
            ],
            tags={"sim2real-behav": CHECK},
        )
        ctx.on_cleanup(lambda n=name: _safe_delete(er, n))
        created_names.add(name)

    page = er.list_schema_mappings(maxResults=1)
    assert len(page["schemaList"]) == 1, f"expected 1 item with maxResults=1, got {len(page['schemaList'])}"
    assert page.get("nextToken"), f"expected a non-empty nextToken, got {page.get('nextToken')!r}"

    seen_names: list[str] = []
    token = None
    for _ in range(500):
        kwargs = {"maxResults": 1}
        if token:
            kwargs["nextToken"] = token
        resp = er.list_schema_mappings(**kwargs)
        assert len(resp["schemaList"]) <= 1, (
            f"maxResults=1 violated: got {len(resp['schemaList'])} items in one page"
        )
        seen_names.extend(s["schemaName"] for s in resp["schemaList"])
        token = resp.get("nextToken")
        if not token:
            break
    else:
        raise AssertionError("pagination did not terminate within 500 pages")

    missing = created_names - set(seen_names)
    assert not missing, f"schema mappings created but never paged to: {missing}"
    dupes = [n for n in set(seen_names) if seen_names.count(n) > 1]
    assert not dupes, f"pagination yielded duplicate schema mappings: {dupes}"


def _safe_delete(er, name):
    try:
        er.delete_schema_mapping(schemaName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
