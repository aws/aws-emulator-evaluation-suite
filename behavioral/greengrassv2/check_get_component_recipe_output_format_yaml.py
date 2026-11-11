"""get-component-recipe-output-format-yaml."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "get-component-recipe-output-format-yaml"
GROUP = "data-plane"
SERVICES = ["greengrassv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetComponent's recipeOutputFormat query parameter actually changes the wire encoding
    of the returned recipe, not just the label on the response."""
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
    arn = ggv2.create_component_version(
        inlineRecipe=json.dumps(recipe).encode("utf-8"),
        tags={"sim2real-check": CHECK},
    )["arn"]
    ctx.on_cleanup(lambda: ggv2.delete_component(arn=arn))
    _poll_until_deployable(ggv2, arn)

    as_json = ggv2.get_component(arn=arn, recipeOutputFormat="JSON")
    assert as_json["recipeOutputFormat"] == "JSON", (
        f"expected recipeOutputFormat echo 'JSON', got {as_json['recipeOutputFormat']!r}"
    )
    parsed = json.loads(as_json["recipe"])
    assert parsed["ComponentName"] == name, (
        f"expected ComponentName {name!r} in JSON recipe, got {parsed.get('ComponentName')!r}"
    )

    as_yaml = ggv2.get_component(arn=arn, recipeOutputFormat="YAML")
    assert as_yaml["recipeOutputFormat"] == "YAML", (
        f"expected recipeOutputFormat echo 'YAML', got {as_yaml['recipeOutputFormat']!r}"
    )
    yaml_text = as_yaml["recipe"].decode("utf-8") if isinstance(as_yaml["recipe"], bytes) else as_yaml["recipe"]
    assert name in yaml_text, f"expected component name {name!r} in YAML recipe body, got {yaml_text!r}"
    assert "1.0.0" in yaml_text, f"expected version '1.0.0' in YAML recipe body, got {yaml_text!r}"

    # A genuine format switch means the YAML body is not itself valid JSON (unquoted mapping keys).
    try:
        json.loads(yaml_text)
        raise AssertionError("YAML-format recipe unexpectedly parsed as JSON -- format was not honored")
    except (json.JSONDecodeError, ValueError):
        pass


def _poll_until_deployable(ggv2, arn: str, timeout_s: float = 60.0, interval_s: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = ggv2.describe_component(arn=arn)["status"]["componentState"]
        if state == "DEPLOYABLE":
            return
        if state == "FAILED":
            raise AssertionError("component reached FAILED state instead of DEPLOYABLE")
        time.sleep(interval_s)
    raise AssertionError("component never reached DEPLOYABLE")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
