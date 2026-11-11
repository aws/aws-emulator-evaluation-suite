"""delete-component-referenced-by-recipe-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-component-referenced-by-recipe-rejected"
GROUP = "overly-permissive"
SERVICES = ["imagebuilder"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteComponent on a component referenced by an image recipe is rejected and the component
    survives; once the referencing recipe is removed, the identical delete call succeeds."""
    ib = ctx.client("imagebuilder")

    # positive control: an unreferenced component deletes cleanly
    unreferenced_arn = _create_component(ctx, suffix="unreferenced", register_cleanup=False)
    ib.delete_component(componentBuildVersionArn=unreferenced_arn)
    code_after, msg_after = _error(lambda: ib.get_component(componentBuildVersionArn=unreferenced_arn))
    assert code_after == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading a deleted component, got {code_after!r}"
    )
    expected_gone = f"The following required resource 'Component' cannot be found: '{unreferenced_arn}'."
    assert msg_after == expected_gone, f"expected message {expected_gone!r}, got {msg_after!r}"

    referenced_arn = _create_component(ctx, suffix="referenced")
    recipe_arn = _create_image_recipe(ctx, referenced_arn)

    code, msg = _error(lambda: ib.delete_component(componentBuildVersionArn=referenced_arn))
    assert code == "ResourceDependencyException", (
        f"expected ResourceDependencyException deleting a component referenced by a recipe, got {code!r}"
    )
    expected = (
        f"Resource dependency error: The resource ARN '{referenced_arn}' has other resources depended on it."
    )
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    # effect absent: the component still exists after the failed delete
    got = ib.get_component(componentBuildVersionArn=referenced_arn)["component"]
    assert got["arn"] == referenced_arn, (
        f"expected component {referenced_arn} to survive the rejected delete, got {got['arn']!r}"
    )

    # restore: remove the dependency, then the identical delete call succeeds
    ib.delete_image_recipe(imageRecipeArn=recipe_arn)
    resp = ib.delete_component(componentBuildVersionArn=referenced_arn)
    assert resp["componentBuildVersionArn"] == referenced_arn, (
        f"expected delete_component to succeed once the referencing recipe is gone, got {resp!r}"
    )

    final_code, final_msg = _error(lambda: ib.get_component(componentBuildVersionArn=referenced_arn))
    assert final_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading the now-deleted component, got {final_code!r}"
    )
    expected_final = f"The following required resource 'Component' cannot be found: '{referenced_arn}'."
    assert final_msg == expected_final, f"expected message {expected_final!r}, got {final_msg!r}"


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_delete_component(ib, arn):
    try:
        ib.delete_component(componentBuildVersionArn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_image_recipe(ib, arn):
    try:
        ib.delete_image_recipe(imageRecipeArn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_component(ctx, version: str = "1.0.0", platform: str = "Linux", suffix: str = "", register_cleanup: bool = True) -> str:
    ib = ctx.client("imagebuilder")
    name = ctx.unique_name(f"sim2real-ib-comp-{suffix}-" if suffix else "sim2real-ib-comp-")
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
        clientToken=str(uuid.uuid4()),
        tags={"sim2real": "true"},
    )
    arn = resp["componentBuildVersionArn"]
    if register_cleanup:
        ctx.on_cleanup(lambda: _safe_delete_component(ib, arn))
    return arn


def _latest_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")["Parameter"][
        "Value"
    ]


def _create_image_recipe(ctx, component_arn: str, version: str = "1.0.0") -> str:
    ib = ctx.client("imagebuilder")
    name = ctx.unique_name("sim2real-ib-recipe-")
    parent = _latest_al2_ami(ctx)
    resp = ib.create_image_recipe(
        name=name,
        semanticVersion=version,
        parentImage=parent,
        components=[{"componentArn": component_arn}],
        clientToken=str(uuid.uuid4()),
        tags={"sim2real": "true"},
    )
    arn = resp["imageRecipeArn"]
    ctx.on_cleanup(lambda: _safe_delete_image_recipe(ib, arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
