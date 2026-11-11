"""component-version-create-describe-get-delete-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "component-version-create-describe-get-delete-lifecycle"
GROUP = "lifecycle"
SERVICES = ["greengrassv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateComponentVersion registers a component that transitions to DEPLOYABLE, its
    recipe/version-list reflect the created version, and DeleteComponent removes it for good."""
    gg = ctx.client("greengrassv2")
    name = ctx.unique_name("sim2real-ggv2-comp-")
    version = "1.0.0"
    resp = gg.create_component_version(
        inlineRecipe=_make_recipe(name, version, "lifecycle test"),
        tags={"env": "sim2real-behavioral"},
    )
    arn = resp["arn"]
    ctx.on_cleanup(lambda: _delete_component_ignore_missing(gg, arn))
    assert resp["componentName"] == name, f"expected componentName {name!r}, got {resp['componentName']!r}"
    assert resp["componentVersion"] == version, (
        f"expected componentVersion {version!r}, got {resp['componentVersion']!r}"
    )

    final_status = _poll_until(
        lambda: gg.describe_component(arn=arn)["status"]["componentState"],
        lambda state: state in ("DEPLOYABLE", "FAILED"),
        timeout_s=90,
        interval_s=3,
    )
    assert final_status == "DEPLOYABLE", f"component did not become deployable: {final_status}"

    described = gg.describe_component(arn=arn)
    assert described["componentName"] == name, (
        f"expected describe_component componentName {name!r}, got {described['componentName']!r}"
    )
    assert described["componentVersion"] == version, (
        f"expected describe_component componentVersion {version!r}, got {described['componentVersion']!r}"
    )

    got = gg.get_component(arn=arn, recipeOutputFormat="JSON")
    recipe = json.loads(got["recipe"])
    assert recipe["ComponentName"] == name, (
        f"expected recipe ComponentName {name!r}, got {recipe['ComponentName']!r}"
    )
    assert recipe["ComponentVersion"] == version, (
        f"expected recipe ComponentVersion {version!r}, got {recipe['ComponentVersion']!r}"
    )

    component_arn = arn.split(":versions:")[0]
    versions = gg.list_component_versions(arn=component_arn)["componentVersions"]
    matching = [v for v in versions if v["arn"] == arn]
    assert len(matching) == 1, f"expected exactly 1 version matching {arn!r}, got {len(matching)}"
    assert matching[0]["componentVersion"] == version, (
        f"expected listed componentVersion {version!r}, got {matching[0]['componentVersion']!r}"
    )

    private_components = gg.list_components(scope="PRIVATE")["components"]
    assert any(c["componentName"] == name for c in private_components), (
        f"expected {name!r} in list_components(scope=PRIVATE), got "
        f"{[c['componentName'] for c in private_components]}"
    )

    gg.delete_component(arn=arn)
    code, message = _error_code(lambda: gg.describe_component(arn=arn))
    assert code == "ResourceNotFoundException", (
        f"expected describe_component on deleted arn to raise ResourceNotFoundException, got {code!r}"
    )
    expected = f"Component ({name}:{version}) does not exist in account {ctx.account}."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    redelete_code, redelete_message = _error_code(lambda: gg.delete_component(arn=arn))
    assert redelete_code == "ResourceNotFoundException", (
        f"expected re-delete of already-deleted arn to raise ResourceNotFoundException, got {redelete_code!r}"
    )
    expected_redelete = f"Component [{name} : {version}] in the accountId [{ctx.account}] does not exist"
    assert redelete_message == expected_redelete, (
        f"expected message {expected_redelete!r}, got {redelete_message!r}"
    )


def _make_recipe(name: str, version: str, description: str) -> bytes:
    recipe = {
        "RecipeFormatVersion": "2020-01-25",
        "ComponentName": name,
        "ComponentVersion": version,
        "ComponentDescription": description,
        "ComponentPublisher": "sim2real",
        "ComponentConfiguration": {"DefaultConfiguration": {"Message": "hello"}},
        "Manifests": [
            {
                "Platform": {"os": "linux"},
                "Lifecycle": {"Run": "echo Hello, {configuration:/Message}."},
            }
        ],
    }
    return json.dumps(recipe).encode("utf-8")


def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


def _delete_component_ignore_missing(gg, arn: str) -> None:
    try:
        gg.delete_component(arn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
