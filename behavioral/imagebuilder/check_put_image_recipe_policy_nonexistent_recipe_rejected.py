"""put-image-recipe-policy-nonexistent-recipe-rejected."""
from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-image-recipe-policy-nonexistent-recipe-rejected"
GROUP = "error-semantics"
SERVICES = ["imagebuilder"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutImageRecipePolicy against an imageRecipeArn that does not exist is rejected as not found."""
    ib = ctx.client("imagebuilder")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bogus_name = ctx.unique_name("sim2real-ib-nonexistent-recipe-")
    bogus_arn = f"arn:aws:imagebuilder:{ctx.region}:{account_id}:image-recipe/{bogus_name}/1.0.0"

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "shareRecipe",
                "Effect": "Allow",
                "Principal": {"AWS": account_id},
                "Action": "imagebuilder:GetImageRecipe",
            }
        ],
    }
    code, msg = _error(lambda: ib.put_image_recipe_policy(imageRecipeArn=bogus_arn, policy=json.dumps(policy)))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"The following required resource 'ImageRecipe' cannot be found: '{bogus_arn}'."
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    # positive control: a real image recipe accepts the same policy shape
    component_arn = _create_component(ctx)
    recipe_arn = _create_image_recipe(ctx, component_arn)
    ib.put_image_recipe_policy(imageRecipeArn=recipe_arn, policy=json.dumps(policy))
    got = json.loads(ib.get_image_recipe_policy(imageRecipeArn=recipe_arn)["policy"])
    assert got["Statement"][0]["Sid"] == "shareRecipe", f"expected Sid 'shareRecipe', got {got!r}"


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
        clientToken=str(uuid.uuid4()),
        tags={"sim2real": CHECK},
    )
    arn = resp["componentBuildVersionArn"]
    ctx.on_cleanup(lambda: ib.delete_component(componentBuildVersionArn=arn))
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
        tags={"sim2real": CHECK},
    )
    arn = resp["imageRecipeArn"]
    ctx.on_cleanup(lambda: ib.delete_image_recipe(imageRecipeArn=arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
