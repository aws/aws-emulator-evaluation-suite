"""associate-glossary-terms-concurrent-modification-rejected."""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-glossary-terms-concurrent-modification-rejected"
GROUP = "concurrency"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent AssociateGlossaryTerms calls on the same asset fail at most once, any loser
    with ConcurrentModificationException; every reported success persists, no failed term leaks
    into the asset, and after a sequential retry the asset carries both terms."""
    glue = ctx.client("glue")

    form_type_name = "SimReal" + _word(ctx.unique_name("form"))
    schema = f"structure {form_type_name} {{\n    tag: String\n}}"
    form_type_id = glue.put_form_type(Name=form_type_name, Schema=schema)["Id"]
    ctx.on_cleanup(lambda: _ignore(lambda: glue.delete_form_type(Identifier=form_type_id)))

    asset_type_name = "SimRealAssetType" + _word(ctx.unique_name("assettype"))
    asset_type_id = glue.put_asset_type(
        Name=asset_type_name, Forms={form_type_name: {"FormTypeIdentifier": form_type_id}}
    )["Id"]
    ctx.on_cleanup(lambda: _ignore(lambda: glue.delete_asset_type(Identifier=asset_type_id)))

    asset_id = ctx.unique_name("sim2real-glue-asset-")
    glue.put_asset(
        AssetTypeId=asset_type_id, Identifier=asset_id, Name="race-asset", Forms={}
    )
    ctx.on_cleanup(lambda: _ignore(lambda: glue.delete_asset(Identifier=asset_id)))

    glossary_id = glue.create_glossary(Name=ctx.unique_name("sim2real-glue-glossary-"))["Id"]
    ctx.on_cleanup(lambda: _ignore(lambda: glue.delete_glossary(Identifier=glossary_id)))
    term1_id = glue.create_glossary_term(GlossaryIdentifier=glossary_id, Name="TermOne")["Id"]
    term2_id = glue.create_glossary_term(GlossaryIdentifier=glossary_id, Name="TermTwo")["Id"]
    ctx.on_cleanup(lambda: _ignore(lambda: glue.delete_glossary_term(Identifier=term1_id)))
    ctx.on_cleanup(lambda: _ignore(lambda: glue.delete_glossary_term(Identifier=term2_id)))

    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(
            glue.associate_glossary_terms,
            AssetIdentifier=asset_id,
            GlossaryTermIdentifiers=[term1_id],
        )
        f2 = pool.submit(
            glue.associate_glossary_terms,
            AssetIdentifier=asset_id,
            GlossaryTermIdentifiers=[term2_id],
        )
        outcomes = []
        for fut, term_id in ((f1, term1_id), (f2, term2_id)):
            try:
                fut.result()
                outcomes.append(("success", term_id, None))
            except ClientError as e:
                outcomes.append((e.response["Error"]["Code"], term_id, e.response["Error"].get("Message")))

    successes = [o for o in outcomes if o[0] == "success"]
    failures = [o for o in outcomes if o[0] != "success"]
    assert len(successes) + len(failures) == 2
    assert len(failures) <= 1, f"expected at most one failure, got {outcomes}"
    for code, _, message in failures:
        assert code == "ConcurrentModificationException", (
            f"expected ConcurrentModificationException for the loser, got {code}"
        )
        # AWS returns an empty JSON object as this conflict's message.
        assert message == "{}", f"expected the message '{{}}', got {message!r}"

    succeeded_terms = {tid for _, tid, _ in successes}
    failed_terms = {tid for _, tid, _ in failures}

    # Effect: every succeeded association actually persisted, and no failed one did --
    # the final state is never a silent partial/corrupted merge.
    asset = glue.get_asset(Identifier=asset_id)
    current_terms = set(asset.get("GlossaryTerms", []))
    assert succeeded_terms <= current_terms, (
        f"succeeded terms {succeeded_terms} missing from final state {current_terms}"
    )
    assert not (failed_terms & current_terms), (
        f"a failed association's term {failed_terms} leaked into final state {current_terms}"
    )

    # Positive control (same file): retrying any failed association sequentially succeeds,
    # and the asset ends up with both terms associated.
    for tid in failed_terms:
        glue.associate_glossary_terms(AssetIdentifier=asset_id, GlossaryTermIdentifiers=[tid])
    after = glue.get_asset(Identifier=asset_id)
    assert set(after.get("GlossaryTerms", [])) == {term1_id, term2_id}



# ===== helpers =====
def _word(raw: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", raw)


def _ignore(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
