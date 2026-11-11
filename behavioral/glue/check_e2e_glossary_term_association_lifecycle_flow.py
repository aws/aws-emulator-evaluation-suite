"""e2e-glossary-term-association-lifecycle-flow."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "e2e-glossary-term-association-lifecycle-flow"
GROUP = "e2e"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A glossary term associated with an asset shows on GetAsset; after DeleteGlossaryTerm the term
    is not found, but the asset's GlossaryTerms still names it (no cross-resource cleanup)."""
    glue = ctx.client("glue")

    form_type_id = _put_form_type(ctx, glue)
    asset_type_id = _put_asset_type(ctx, glue, form_type_id)
    asset_id = _put_asset(ctx, glue, asset_type_id, form_type_id)

    glossary_id = glue.create_glossary(Name=ctx.unique_name("sim2real-glossary-"))["Id"]
    ctx.on_cleanup(lambda: glue.delete_glossary(Identifier=glossary_id))

    term = glue.create_glossary_term(
        GlossaryIdentifier=glossary_id,
        Name=ctx.unique_name("sim2real-term-"),
        ShortDescription="a term used in a behavioral fidelity check",
    )
    term_id = term["Id"]
    # Cleanup for an early failure, so DeleteGlossary can succeed.
    ctx.on_cleanup(lambda: _safe_delete_term(glue, term_id))

    fetched_term = glue.get_glossary_term(Identifier=term_id)
    assert fetched_term["Id"] == term_id, (
        f"GetGlossaryTerm returned Id={fetched_term['Id']!r}, expected {term_id!r}"
    )
    assert fetched_term["GlossaryId"] == glossary_id, (
        f"GetGlossaryTerm returned GlossaryId={fetched_term['GlossaryId']!r}, "
        f"expected {glossary_id!r}"
    )

    assoc = glue.associate_glossary_terms(
        AssetIdentifier=asset_id, GlossaryTermIdentifiers=[term_id]
    )
    assert assoc["GlossaryTerms"] == [term_id], (
        f"AssociateGlossaryTerms returned GlossaryTerms={assoc['GlossaryTerms']!r}, "
        f"expected [{term_id!r}]"
    )

    asset_after_associate = glue.get_asset(Identifier=asset_id)
    assert term_id in asset_after_associate["GlossaryTerms"], (
        f"expected {term_id!r} in GetAsset GlossaryTerms="
        f"{asset_after_associate['GlossaryTerms']!r} after AssociateGlossaryTerms succeeded"
    )

    glue.delete_glossary_term(Identifier=term_id)

    code, message = _error(lambda: glue.get_glossary_term(Identifier=term_id))
    assert code == "EntityNotFoundException", (
        f"expected GetGlossaryTerm on the deleted term to be EntityNotFoundException, got {code!r}"
    )
    expected = f'{{"Message":"Business glossary term {term_id} not found."}}'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    asset_after_delete = glue.get_asset(Identifier=asset_id)
    assert term_id in asset_after_delete.get("GlossaryTerms", []), asset_after_delete



# ===== helpers =====
def _error(fn):
    """Return the (code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError rejection, but the call SUCCEEDED: {result!r}")


def _safe_delete_term(glue, term_id):
    from botocore.exceptions import ClientError

    try:
        glue.delete_glossary_term(Identifier=term_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _put_form_type(ctx, glue):
    name = "SimFormType" + _word_suffix(ctx)
    schema = "structure %s {\n    note: String\n}" % name
    resp = glue.put_form_type(Name=name, Schema=schema)
    ctx.on_cleanup(lambda: glue.delete_form_type(Identifier=resp["Id"]))
    return resp["Id"]


def _word_suffix(ctx):
    return "".join(ch for ch in ctx.unique_name("x") if ch.isalnum())[-12:]


def _put_asset_type(ctx, glue, form_type_id):
    name = "SimAssetType" + _word_suffix(ctx)
    resp = glue.put_asset_type(
        Name=name, Forms={"Details": {"FormTypeIdentifier": form_type_id}}
    )
    ctx.on_cleanup(lambda: glue.delete_asset_type(Identifier=resp["Id"]))
    return resp["Id"]


def _put_asset(ctx, glue, asset_type_id, form_type_id):
    asset_id = ctx.unique_name("sim2real-asset-")
    resp = glue.put_asset(
        AssetTypeId=asset_type_id,
        Identifier=asset_id,
        Name="Behavioral fidelity check asset",
        Forms={"Details": {"FormTypeId": form_type_id, "Content": '{"note":"sim2real"}'}},
    )
    ctx.on_cleanup(lambda: glue.delete_asset(Identifier=resp["Id"]))
    return resp["Id"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
