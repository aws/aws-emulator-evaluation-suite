"""list-transformers-pagination-maxresults."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-transformers-pagination-maxresults"
GROUP = "list"
SERVICES = ["b2bi"]


def _create_transformer(ctx) -> str:
    b2bi = ctx.client("b2bi")
    name = ctx.unique_name("sim2real-b2bi-tr-")
    resp = b2bi.create_transformer(
        name=name,
        inputConversion={
            "fromFormat": "X12",
            "formatOptions": {"x12": {"transactionSet": "X12_850", "version": "VERSION_4010"}},
        },
        mapping={"templateLanguage": "JSONATA", "template": "$"},
    )
    transformer_id = resp["transformerId"]
    ctx.on_cleanup(lambda: b2bi.delete_transformer(transformerId=transformer_id))
    # Transformers are created Inactive; a capability can only reference an active one.
    b2bi.update_transformer(transformerId=transformer_id, status="active")
    return transformer_id


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTransformers with maxResults=1 returns exactly one item per page and a
    nextToken that lets the caller walk the full result set -- pagination is real, not a
    single-page stub that ignores maxResults."""
    b2bi = ctx.client("b2bi")
    created_ids = {_create_transformer(ctx) for _ in range(3)}

    first_page = b2bi.list_transformers(maxResults=1)
    assert len(first_page["transformers"]) == 1, (
        f"maxResults=1 must cap the page at exactly one item, got {first_page['transformers']!r}"
    )
    assert first_page.get("nextToken"), "expected a nextToken when more results remain"

    seen_ids: set[str] = {t["transformerId"] for t in first_page["transformers"]}
    next_token = first_page["nextToken"]
    for _ in range(50):
        page = b2bi.list_transformers(maxResults=1, nextToken=next_token)
        assert len(page["transformers"]) <= 1, (
            f"maxResults=1 must cap every page at one item, got {page['transformers']!r}"
        )
        seen_ids.update(t["transformerId"] for t in page["transformers"])
        next_token = page.get("nextToken")
        if not next_token:
            break

    assert created_ids <= seen_ids, (
        f"expected all created transformers {created_ids} to surface via pagination, saw {seen_ids}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
