"""create-image-recipe-duplicate-version-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-image-recipe-duplicate-version-rejected"
GROUP = "error-semantics"
SERVICES = ["imagebuilder"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateImageRecipe with a name+semanticVersion already registered is rejected; the block leaves
    no second recipe registered, is scoped to that exact key, and lifts once the recipe is deleted."""
    ib = ctx.client("imagebuilder")
    component_arn = _create_component(ctx)
    parent = _latest_al2_ami(ctx)

    name = ctx.unique_name("sim2real-ib-recipe-")
    created = ib.create_image_recipe(
        name=name,
        semanticVersion="1.0.0",
        parentImage=parent,
        components=[{"componentArn": component_arn}],
        tags={"sim2real": CHECK},
        clientToken=str(uuid.uuid4()),
    )
    recipe_arn = created["imageRecipeArn"]

    code, msg = _error(
        lambda: ib.create_image_recipe(
            name=name,
            semanticVersion="1.0.0",
            parentImage=parent,
            components=[{"componentArn": component_arn}],
            clientToken=str(uuid.uuid4()),
        )
    )
    assert code == "ResourceAlreadyExistsException", f"expected ResourceAlreadyExistsException, got {code!r}"
    expected = f"The following resource 'ImageRecipe' already exists: '{recipe_arn}'."
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    # effect absent: the rejected duplicate did not register a second recipe under this name
    listed = [
        r["arn"]
        for r in ib.list_image_recipes(filters=[{"name": "name", "values": [name]}])["imageRecipeSummaryList"]
    ]
    assert listed == [recipe_arn], f"expected only {recipe_arn!r} listed, got {listed!r}"

    # positive control: a different semanticVersion on the same name is unaffected by the block
    other_arn = ib.create_image_recipe(
        name=name,
        semanticVersion="1.0.1",
        parentImage=parent,
        components=[{"componentArn": component_arn}],
        tags={"sim2real": CHECK},
        clientToken=str(uuid.uuid4()),
    )["imageRecipeArn"]
    ctx.on_cleanup(lambda: ib.delete_image_recipe(imageRecipeArn=other_arn))
    other_fetched = ib.get_image_recipe(imageRecipeArn=other_arn)["imageRecipe"]
    assert other_fetched["version"] == "1.0.1", f"expected version 1.0.1, got {other_fetched['version']!r}"

    # restore: deleting the original registration lifts the block on the exact key
    ib.delete_image_recipe(imageRecipeArn=recipe_arn)
    code_after_delete, msg_after_delete = _error(lambda: ib.get_image_recipe(imageRecipeArn=recipe_arn))
    assert code_after_delete == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code_after_delete!r}"
    expected = f"The following required resource 'ImageRecipe' cannot be found: '{recipe_arn}'."
    assert msg_after_delete == expected, f"expected message {expected!r}, got {msg_after_delete!r}"

    restored_arn = ib.create_image_recipe(
        name=name,
        semanticVersion="1.0.0",
        parentImage=parent,
        components=[{"componentArn": component_arn}],
        tags={"sim2real": CHECK},
        clientToken=str(uuid.uuid4()),
    )["imageRecipeArn"]
    ctx.on_cleanup(lambda: ib.delete_image_recipe(imageRecipeArn=restored_arn))
    restored_fetched = ib.get_image_recipe(imageRecipeArn=restored_arn)["imageRecipe"]
    assert restored_fetched["version"] == "1.0.0", f"expected version 1.0.0, got {restored_fetched['version']!r}"


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_component(ctx, version: str = "1.0.0", platform: str = "Linux") -> str:
    ib = ctx.client("imagebuilder")
    name = ctx.unique_name("sim2real-ib-comp-")
    doc = (
        f"name: {name}\n"
        "description: test component\n"
        "schemaVersion: 1.0\n"
        "phases:\n"
        "  - name: build\n"
        "    steps:\n"
        "      - name: UpdateOS\n"
        "        action: UpdateOS\n"
    )
    resp = ib.create_component(
        name=name,
        semanticVersion=version,
        platform=platform,
        data=doc,
        tags={"sim2real": CHECK},
        clientToken=str(uuid.uuid4()),
    )
    arn = resp["componentBuildVersionArn"]
    ctx.on_cleanup(lambda: ib.delete_component(componentBuildVersionArn=arn))
    return arn


def _latest_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")["Parameter"][
        "Value"
    ]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
