"""e2e-glossary-associate-nonexistent-term-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "e2e-glossary-associate-nonexistent-term-rejected"
GROUP = "e2e"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateGlossaryTerms with a well-formed but nonexistent term id raises
    InvalidInputException with the exact message and leaves the asset with no terms; associating
    a real term then succeeds.
    """
    glue = ctx.client("glue")

    form_type_id = _put_form_type(ctx, glue)
    asset_type_id = _put_asset_type(ctx, glue, form_type_id)
    asset_id = _put_asset(ctx, glue, asset_type_id, form_type_id)

    glossary_id = glue.create_glossary(Name=ctx.unique_name("sim2real-glossary-"))["Id"]
    ctx.on_cleanup(lambda: glue.delete_glossary(Identifier=glossary_id))
    real_term_id = glue.create_glossary_term(
        GlossaryIdentifier=glossary_id, Name=ctx.unique_name("sim2real-term-")
    )["Id"]
    ctx.on_cleanup(lambda: glue.delete_glossary_term(Identifier=real_term_id))

    # Real glossary term ids are short lowercase-alphanumeric tokens (e.g. "avugvxvsul6izr");
    # use a same-shaped-but-nonexistent id so the service's format validation passes and we
    # actually reach the existence check.
    bogus_term_id = "zzzznonexist99"

    code, message = _error(
        lambda: glue.associate_glossary_terms(
            AssetIdentifier=asset_id, GlossaryTermIdentifiers=[bogus_term_id]
        )
    )
    assert code == "InvalidInputException", f"expected InvalidInputException, got {code!r}"
    expected = f'{{"Message":"Glossary term not found: {bogus_term_id}"}}'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the failed call must not have attached the bogus term.
    asset = glue.get_asset(Identifier=asset_id)
    assert bogus_term_id not in asset.get("GlossaryTerms", []), (
        f"bogus term {bogus_term_id!r} was attached despite the rejected call: "
        f"{asset.get('GlossaryTerms')!r}"
    )
    assert asset.get("GlossaryTerms", []) == [], (
        f"expected no glossary terms on a freshly created asset, got {asset.get('GlossaryTerms')!r}"
    )

    # Positive control: associating the real term on the same asset works.
    assoc = glue.associate_glossary_terms(
        AssetIdentifier=asset_id, GlossaryTermIdentifiers=[real_term_id]
    )
    assert assoc["GlossaryTerms"] == [real_term_id], (
        f"expected [{real_term_id!r}], got {assoc['GlossaryTerms']!r}"
    )
    asset_after = glue.get_asset(Identifier=asset_id)
    assert real_term_id in asset_after["GlossaryTerms"], (
        f"expected {real_term_id!r} in {asset_after['GlossaryTerms']!r} after a successful associate"
    )


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError rejection, but the call SUCCEEDED: {result!r}")


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
