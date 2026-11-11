"""create-image-recipe-invalid-semantic-version-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-image-recipe-invalid-semantic-version-rejected"
GROUP = "overly-permissive"
SERVICES = ["imagebuilder"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateImageRecipe rejects a semanticVersion node value that exceeds the 2^30-1 upper bound, and nothing is registered."""
    ib = ctx.client("imagebuilder")
    name = ctx.unique_name("sim2real-recipe-")
    parent_image = f"arn:aws:imagebuilder:{ctx.region}:aws:image/amazon-linux-2-x86/x.x.x"

    code, msg = _error(
        lambda: ib.create_image_recipe(
            name=name,
            semanticVersion="9999999999.0.0",
            parentImage=parent_image,
            clientToken=str(uuid.uuid4()),
        )
    )
    assert code == "InvalidParameterValueException", f"expected InvalidParameterValueException, got {code!r}"
    expected = (
        "The value supplied for parameter 'semanticVersion' is not valid. "
        "The supplied semantic version does not follow the required format. "
        "Only one 'x' wildcard is allowed per version."
    )
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    # effect absent: no recipe was registered under this name
    found = ib.list_image_recipes(filters=[{"name": "name", "values": [name]}])["imageRecipeSummaryList"]
    assert found == [], f"expected no recipe registered under {name!r}, found {found!r}"

    # positive control: a syntactically valid semantic version succeeds
    control_arn = ib.create_image_recipe(
        name=name,
        semanticVersion="1.0.0",
        parentImage=parent_image,
        clientToken=str(uuid.uuid4()),
        tags={"sim2real-check": CHECK},
    )["imageRecipeArn"]
    ctx.on_cleanup(lambda: ib.delete_image_recipe(imageRecipeArn=control_arn))


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
