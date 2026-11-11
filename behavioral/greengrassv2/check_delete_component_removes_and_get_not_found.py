"""delete-component-removes-and-get-not-found."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-component-removes-and-get-not-found"
GROUP = "state"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteComponent, the version is gone: GetComponent and DescribeComponent 404, and it
    drops from both ListComponentVersions and ListComponents."""
    ggv2 = ctx.client("greengrassv2")
    name = ctx.unique_name("sim2real-ggv2-comp-")
    recipe = {
        "RecipeFormatVersion": "2020-01-25",
        "ComponentName": name,
        "ComponentVersion": "1.0.0",
        "ComponentDescription": "sim2real behavioral test component",
        "ComponentPublisher": "sim2real-tests",
        "ComponentConfiguration": {"DefaultConfiguration": {}},
        "Manifests": [{"Platform": {"os": "linux"}, "Lifecycle": {}}],
    }
    arn = ggv2.create_component_version(inlineRecipe=json.dumps(recipe).encode("utf-8"))["arn"]
    ctx.on_cleanup(lambda: _delete_component_cleanup(ggv2, arn))
    component_arn = arn.split(":versions:")[0]

    # Sanity: it exists before deletion, in both reads and both listings.
    ggv2.describe_component(arn=arn)
    versions_before = [v["arn"] for v in ggv2.list_component_versions(arn=component_arn)["componentVersions"]]
    assert arn in versions_before, f"expected {arn} in ListComponentVersions before delete, got {versions_before}"
    names_before = [c["componentName"] for c in ggv2.list_components(scope="PRIVATE")["components"]]
    assert name in names_before, f"expected {name} in ListComponents before delete, got {names_before}"

    ggv2.delete_component(arn=arn)

    account = arn.split(":")[4]
    not_found = (
        "ResourceNotFoundException",
        f"PRIVATE component ({name}:1.0.0) under account {account} does not exist",
    )
    get_err = _error(lambda: ggv2.get_component(arn=arn))
    assert get_err == not_found, (
        f"expected {not_found!r} from GetComponent after delete, got {get_err!r}"
    )
    describe_not_found = (
        "ResourceNotFoundException",
        f"Component ({name}:1.0.0) does not exist in account {account}.",
    )
    describe_err = _error(lambda: ggv2.describe_component(arn=arn))
    assert describe_err == describe_not_found, (
        f"expected {describe_not_found!r} from DescribeComponent after delete, got {describe_err!r}"
    )

    versions_after = _list_component_versions_or_not_found(ggv2, component_arn)
    assert arn not in versions_after, f"deleted version still in ListComponentVersions: {versions_after}"
    names_after = [c["componentName"] for c in ggv2.list_components(scope="PRIVATE")["components"]]
    assert name not in names_after, f"deleted component still in ListComponents: {names_after}"


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). A call that succeeds raises: an
    emulator accepting what AWS refuses must fail loudly, not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_component_cleanup(ggv2, arn):
    try:
        ggv2.delete_component(arn=arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _list_component_versions_or_not_found(ggv2, component_arn):
    """The sole version was just deleted, so the component itself may also be gone: treat
    ResourceNotFoundException on the listing call the same as an empty/absent listing."""
    try:
        return [v["arn"] for v in ggv2.list_component_versions(arn=component_arn)["componentVersions"]]
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return []
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
