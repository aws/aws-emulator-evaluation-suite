"""list-glossaries-reflects-creation-and-deletion."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-glossaries-reflects-creation-and-deletion"
GROUP = "representation"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListGlossaries pages every glossary in the catalog by Id, and a deleted glossary
    stops appearing on the next listing while its siblings remain.
    """
    glue = ctx.client("glue")

    kept_a = _create_glossary(ctx, glue, "Alpha")
    kept_b = _create_glossary(ctx, glue, "Beta")
    doomed = _create_glossary(ctx, glue, "Gamma")

    before_ids = _list_all_glossary_ids(glue)
    for created in (kept_a, kept_b, doomed):
        assert created["Id"] in before_ids, (
            f"expected ListGlossaries to include {created['Id']!r} right after CreateGlossary, "
            f"got {len(before_ids)} ids"
        )

    glue.delete_glossary(Identifier=doomed["Id"])

    after_ids = _list_all_glossary_ids(glue)
    assert doomed["Id"] not in after_ids, (
        f"expected the deleted glossary {doomed['Id']!r} to drop out of ListGlossaries, "
        f"but it is still present"
    )
    for created in (kept_a, kept_b):
        assert created["Id"] in after_ids, (
            f"expected the untouched glossary {created['Id']!r} to remain in ListGlossaries "
            f"after an unrelated delete, got {len(after_ids)} ids"
        )


def _create_glossary(ctx, glue, suffix: str) -> dict:
    name = ctx.unique_name(f"sim2real-glue-glossary-{suffix}-")
    created = glue.create_glossary(Name=name, Description=f"{suffix} glossary for fidelity testing")
    glossary_id = created["Id"]
    ctx.on_cleanup(lambda: _delete_glossary_idempotent(glue, glossary_id))
    return created


def _delete_glossary_idempotent(glue, glossary_id: str) -> None:
    """Tear down a glossary the check may have already deleted mid-run."""
    try:
        glue.delete_glossary(Identifier=glossary_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _list_all_glossary_ids(glue) -> set[str]:
    ids: set[str] = set()
    next_token = None
    while True:
        kwargs = {"MaxResults": 1}
        if next_token:
            kwargs["NextToken"] = next_token
        page = glue.list_glossaries(**kwargs)
        ids.update(item["Id"] for item in page.get("Items", []))
        next_token = page.get("NextToken")
        if not next_token:
            return ids


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
