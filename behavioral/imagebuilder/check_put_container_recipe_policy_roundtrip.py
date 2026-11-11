"""put-container-recipe-policy-roundtrip."""
from __future__ import annotations

import json
import uuid

from behavioral_harness import tags

CHECK = "put-container-recipe-policy-roundtrip"
GROUP = "component-data-plane"
SERVICES = ["imagebuilder"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutContainerRecipePolicy attaches a resource policy that GetContainerRecipePolicy returns verbatim."""
    ib = ctx.client("imagebuilder")
    ecr = ctx.client("ecr")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    component_arn = _create_component(ctx)
    repo_name = ctx.unique_name("sim2real-ib-repo-").lower()
    ecr.create_repository(repositoryName=repo_name, tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

    recipe_name = ctx.unique_name("sim2real-ib-container-recipe-")
    dockerfile_template = (
        "FROM {{ imagebuilder:parentImage }}\n{{ imagebuilder:environments }}\n{{ imagebuilder:components }}\n"
    )
    resp = ib.create_container_recipe(
        name=recipe_name,
        semanticVersion="1.0.0",
        containerType="DOCKER",
        parentImage="amazonlinux:2",
        components=[{"componentArn": component_arn}],
        targetRepository={"service": "ECR", "repositoryName": repo_name},
        dockerfileTemplateData=dockerfile_template,
        clientToken=str(uuid.uuid4()),
        tags={"sim2real-check": CHECK},
    )
    recipe_arn = resp["containerRecipeArn"]
    ctx.on_cleanup(lambda: ib.delete_container_recipe(containerRecipeArn=recipe_arn))

    principal_arn = f"arn:aws:iam::{account_id}:root"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "shareContainerRecipe",
                "Effect": "Allow",
                "Principal": {"AWS": [principal_arn]},
                "Action": ["imagebuilder:GetContainerRecipe"],
                "Resource": [recipe_arn],
            }
        ],
    }
    ib.put_container_recipe_policy(containerRecipeArn=recipe_arn, policy=json.dumps(policy_doc))

    got = json.loads(ib.get_container_recipe_policy(containerRecipeArn=recipe_arn)["policy"])
    got_stmt = got["Statement"][0]
    assert got_stmt["Sid"] == "shareContainerRecipe", f"expected Sid 'shareContainerRecipe', got {got_stmt.get('Sid')!r}"
    assert got_stmt["Effect"] == "Allow", f"expected Effect 'Allow', got {got_stmt.get('Effect')!r}"
    assert got_stmt["Action"] == ["imagebuilder:GetContainerRecipe"], f"expected Action ['imagebuilder:GetContainerRecipe'], got {got_stmt.get('Action')!r}"
    assert got_stmt["Principal"]["AWS"] == principal_arn, f"expected Principal.AWS {principal_arn!r}, got {got_stmt.get('Principal')!r}"
    assert got_stmt["Resource"] == [recipe_arn], f"expected Resource {[recipe_arn]!r}, got {got_stmt.get('Resource')!r}"


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
        clientToken=str(uuid.uuid4()),
        tags={"sim2real-check": CHECK},
    )
    arn = resp["componentBuildVersionArn"]
    ctx.on_cleanup(lambda: ib.delete_component(componentBuildVersionArn=arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
