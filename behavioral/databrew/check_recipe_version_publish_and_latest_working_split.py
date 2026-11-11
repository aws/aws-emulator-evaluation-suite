"""recipe-version-publish-and-latest-working-split."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "recipe-version-publish-and-latest-working-split"
GROUP = "recipes"
SERVICES = ["databrew"]

STEP_UPPER = {"Action": {"Operation": "UPPER_CASE", "Parameters": {"sourceColumn": "dept"}}}
STEP_RENAME = {
    "Action": {"Operation": "RENAME", "Parameters": {"sourceColumn": "dept", "targetColumn": "DEPARTMENT"}}
}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A recipe's draft goes 0.1 -> 1.1 while publishes mint 1.0 and 2.0 that stay frozen and are the only
    ListRecipeVersions entries; DeleteRecipeVersion on LATEST_WORKING raises ValidationException, while
    BatchDeleteRecipeVersion reports ErrorCode "409" and "404" items inside a 200."""
    db = ctx.client("databrew")

    recipe = ctx.unique_name("sim2real-behav-databrew-rc-")
    db.create_recipe(Name=recipe, Description="draft", Steps=[STEP_UPPER])
    ctx.on_cleanup(lambda: _delete_recipe(db, recipe))

    draft = db.describe_recipe(Name=recipe, RecipeVersion="LATEST_WORKING")
    if draft["RecipeVersion"] != "0.1":
        raise AssertionError(f"a new recipe's draft version was {draft['RecipeVersion']!r}, expected '0.1'")

    code, message = _rejected(
        "a versionless describe before the first publish", lambda: db.describe_recipe(Name=recipe)
    )
    if code != "ResourceNotFoundException":
        raise AssertionError(f"versionless describe before publish raised {code}: {message!r}")
    if message != f"The recipe {recipe} for version LATEST_PUBLISHED wasn't found.":
        raise AssertionError(
            f"the rejection does not show that the versionless default is LATEST_PUBLISHED: {message!r}"
        )

    db.publish_recipe(Name=recipe, Description="first")
    published = db.describe_recipe(Name=recipe)
    if published["RecipeVersion"] != "1.0":
        raise AssertionError(f"the first publish minted {published['RecipeVersion']!r}, expected '1.0'")
    if len(published["Steps"]) != 1:
        raise AssertionError(f"published 1.0 has {len(published['Steps'])} steps, expected 1")

    db.update_recipe(Name=recipe, Steps=[STEP_UPPER, STEP_RENAME], Description="draft 2")
    draft = db.describe_recipe(Name=recipe, RecipeVersion="LATEST_WORKING")
    if draft["RecipeVersion"] != "1.1":
        raise AssertionError(
            f"updating the draft after one publish gave {draft['RecipeVersion']!r}, expected '1.1'"
        )
    if len(draft["Steps"]) != 2:
        raise AssertionError(f"the updated draft has {len(draft['Steps'])} steps, expected 2")

    frozen = db.describe_recipe(Name=recipe, RecipeVersion="1.0")
    if len(frozen["Steps"]) != 1:
        raise AssertionError(
            f"UpdateRecipe leaked into published 1.0, which now has {len(frozen['Steps'])} steps"
        )

    db.publish_recipe(Name=recipe, Description="second")
    published = db.describe_recipe(Name=recipe)
    if published["RecipeVersion"] != "2.0":
        raise AssertionError(f"the second publish minted {published['RecipeVersion']!r}, expected '2.0'")
    if len(published["Steps"]) != 2:
        raise AssertionError(f"published 2.0 has {len(published['Steps'])} steps, expected 2")
    frozen = db.describe_recipe(Name=recipe, RecipeVersion="1.0")
    if len(frozen["Steps"]) != 1:
        raise AssertionError(
            f"a later publish mutated published 1.0, which now has {len(frozen['Steps'])} steps"
        )

    listed = sorted(
        r["RecipeVersion"]
        for page in db.get_paginator("list_recipe_versions").paginate(Name=recipe)
        for r in page.get("Recipes", [])
    )
    if listed != ["1.0", "2.0"]:
        raise AssertionError(f"ListRecipeVersions returned {listed}, expected ['1.0', '2.0']")

    # ---- the draft is undeletable, and the two delete APIs disagree about HOW to say so
    code, message = _rejected(
        "DeleteRecipeVersion on the draft",
        lambda: db.delete_recipe_version(Name=recipe, RecipeVersion="LATEST_WORKING"),
    )
    if code != "ValidationException":
        raise AssertionError(f"DeleteRecipeVersion on LATEST_WORKING raised {code}: {message!r}")
    if message != "Recipe version LATEST_WORKING is not allowed to be deleted":
        raise AssertionError(f"unexpected rejection for deleting the draft: {message!r}")

    batched = db.batch_delete_recipe_version(Name=recipe, RecipeVersions=["LATEST_WORKING"])
    errors = batched.get("Errors") or []
    if len(errors) != 1:
        raise AssertionError(
            f"BatchDeleteRecipeVersion on the draft reported {errors}, expected one per-item error"
        )
    if errors[0].get("ErrorCode") != "409":
        raise AssertionError(f"expected a per-item ErrorCode of '409', got {errors[0]!r}")
    expected = f"Recipe {recipe} version LATEST_WORKING can only be deleted if all other versions got deleted."
    if errors[0].get("ErrorMessage") != expected:
        raise AssertionError(f"unexpected per-item message: {errors[0]!r}")

    batched = db.batch_delete_recipe_version(Name=recipe, RecipeVersions=["9.0"])
    errors = batched.get("Errors") or []
    if len(errors) != 1 or errors[0].get("ErrorCode") != "404":
        raise AssertionError(
            f"deleting a version that does not exist reported {errors}, expected one '404' item"
        )
    if errors[0].get("ErrorMessage") != f"The recipe {recipe} version 9.0 wasn't found.":
        raise AssertionError(f"unexpected per-item message for a missing version: {errors[0]!r}")

    # ---- the positive control for that pair: published versions DO delete, in order
    for version in ("1.0", "2.0"):
        errors = db.batch_delete_recipe_version(
            Name=recipe, RecipeVersions=[version]
        ).get("Errors") or []
        if errors:
            raise AssertionError(f"deleting published {version} was refused: {errors}")
    remaining = sorted(
        r["RecipeVersion"]
        for page in db.get_paginator("list_recipe_versions").paginate(Name=recipe)
        for r in page.get("Recipes", [])
    )
    if remaining:
        raise AssertionError(f"published versions survived their own delete: {remaining}")

    # With every published version gone the draft is now deletable -- the 409 above was about
    # ordering, not about the draft being permanent.
    errors = db.batch_delete_recipe_version(
        Name=recipe, RecipeVersions=["LATEST_WORKING"]
    ).get("Errors") or []
    if errors:
        raise AssertionError(f"the draft was still refused after every publish was deleted: {errors}")
    code, message = _rejected(
        "describing the draft of a fully deleted recipe",
        lambda: db.describe_recipe(Name=recipe, RecipeVersion="LATEST_WORKING"),
    )
    if code != "ResourceNotFoundException":
        raise AssertionError(f"a fully deleted recipe still describes; got {code}")
    if message != f"The recipe {recipe} for version LATEST_WORKING wasn't found.":
        raise AssertionError(f"unexpected not-found message for a fully deleted recipe: {message!r}")


def _rejected(label, fn):
    """The (code, message) of the ClientError ``fn`` must raise. An unexpected success is the
    divergence this helper exists to surface, so it raises rather than returning a sentinel."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"{label} was ACCEPTED, but real AWS rejects it")


def _delete_recipe(db, name):
    """BatchDeleteRecipeVersion answers HTTP 200 with a per-item `Errors` array instead of
    raising, and refuses LATEST_WORKING while any published version survives -- so published
    versions go first and the per-item result is READ rather than assumed. This check deletes the
    recipe itself as its closing assertion, so an already-gone recipe is not an error here."""
    try:
        published = [
            r["RecipeVersion"]
            for page in db.get_paginator("list_recipe_versions").paginate(Name=name)
            for r in page.get("Recipes", [])
        ]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return
        raise
    for version in published:
        db.batch_delete_recipe_version(Name=name, RecipeVersions=[version])
    try:
        errors = db.batch_delete_recipe_version(
            Name=name, RecipeVersions=["LATEST_WORKING"]
        ).get("Errors") or []
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return
        raise
    if errors and not all((e.get("ErrorCode") == "404") for e in errors):
        raise AssertionError(f"recipe {name} was not removed: {errors}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
