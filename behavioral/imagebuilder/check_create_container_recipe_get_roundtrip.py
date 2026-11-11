"""create-container-recipe-get-roundtrip."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "create-container-recipe-get-roundtrip"
GROUP = "control-plane"
SERVICES = ["imagebuilder"]

_COMPONENT_DATA = """
name: sim2real-test-component
description: minimal test component
schemaVersion: 1.0

phases:
  - name: build
    steps:
      - name: HelloWorldStep
        action: ExecuteBash
        inputs:
          commands:
            - echo "hello world"
""".strip()


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateContainerRecipe persists containerType/targetRepository/parentImage exactly as submitted."""
    ib = ctx.client("imagebuilder")
    ecr = ctx.client("ecr")

    component_arn = _create_component(ctx, ib)

    repo_name = ctx.unique_name("sim2real-ib-repo-").lower()
    ecr.create_repository(repositoryName=repo_name, tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

    recipe_name = ctx.unique_name("sim2real-container-recipe-")
    dockerfile_template = "FROM {{ imagebuilder:parentImage }}\n{{ imagebuilder:environments }}\n{{ imagebuilder:components }}\n"
    resp = ib.create_container_recipe(
        name=recipe_name,
        semanticVersion="1.0.0",
        containerType="DOCKER",
        parentImage="amazonlinux:2",
        components=[{"componentArn": component_arn}],
        targetRepository={"service": "ECR", "repositoryName": repo_name},
        dockerfileTemplateData=dockerfile_template,
        clientToken=str(uuid.uuid4()),
        tags={"sim2real": CHECK},
    )
    recipe_arn = resp["containerRecipeArn"]
    ctx.on_cleanup(lambda: ib.delete_container_recipe(containerRecipeArn=recipe_arn))

    got = ib.get_container_recipe(containerRecipeArn=recipe_arn)["containerRecipe"]
    assert got["arn"] == recipe_arn, f"expected arn {recipe_arn!r}, got {got['arn']!r}"
    assert got["containerType"] == "DOCKER", f"expected containerType DOCKER, got {got['containerType']!r}"
    assert got["parentImage"] == "amazonlinux:2", f"expected parentImage amazonlinux:2, got {got['parentImage']!r}"
    assert got["targetRepository"] == {"service": "ECR", "repositoryName": repo_name}, (
        f"expected targetRepository {{'service': 'ECR', 'repositoryName': {repo_name!r}}}, "
        f"got {got['targetRepository']!r}"
    )
    assert got["components"][0]["componentArn"] == component_arn, (
        f"expected components[0].componentArn {component_arn!r}, got {got['components'][0]['componentArn']!r}"
    )


def _create_component(ctx, ib):
    name = ctx.unique_name("sim2real-component-")
    resp = ib.create_component(
        name=name,
        semanticVersion="1.0.0",
        platform="Linux",
        data=_COMPONENT_DATA,
        clientToken=str(uuid.uuid4()),
        tags={"sim2real": CHECK},
    )
    arn = resp["componentBuildVersionArn"]
    ctx.on_cleanup(lambda: ib.delete_component(componentBuildVersionArn=arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
