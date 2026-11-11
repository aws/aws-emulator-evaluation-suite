"""create-theme-roundtrip-nested-values."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-theme-roundtrip-nested-values"
GROUP = "lifecycle"
SERVICES = ["amplifyuibuilder"]

_ENV = "staging"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTheme persists a theme with nested (parent/child) values and an overrides list, and
    GetTheme returns the exact same nested structure back."""
    app_id = _create_app(ctx)
    uib = ctx.client("amplifyuibuilder")
    name = ctx.unique_name("sim2real-theme-").replace("-", "")
    name = name[0].upper() + name[1:]

    theme_to_create = {
        "name": name,
        "values": [
            {
                "key": "colors",
                "value": {
                    "children": [
                        {"key": "primary", "value": {"value": "#0000ff"}},
                        {
                            "key": "font",
                            "value": {
                                "children": [
                                    {"key": "size", "value": {"value": "16"}},
                                    {"key": "weight", "value": {"value": "bold"}},
                                ]
                            },
                        },
                    ]
                },
            }
        ],
        "overrides": [
            {
                "key": "colors",
                "value": {"children": [{"key": "primary", "value": {"value": "#ff00ff"}}]},
            }
        ],
    }

    created = uib.create_theme(appId=app_id, environmentName=_ENV, themeToCreate=theme_to_create)[
        "entity"
    ]
    theme_id = created["id"]
    ctx.on_cleanup(lambda: uib.delete_theme(appId=app_id, environmentName=_ENV, id=theme_id))

    got = uib.get_theme(appId=app_id, environmentName=_ENV, id=theme_id)["theme"]

    assert got["name"] == name
    values_by_key = {v["key"]: v["value"] for v in got["values"]}
    colors_children = {c["key"]: c["value"] for c in values_by_key["colors"]["children"]}
    assert colors_children["primary"]["value"] == "#0000ff"
    font_children = {c["key"]: c["value"] for c in colors_children["font"]["children"]}
    assert font_children["size"]["value"] == "16"
    assert font_children["weight"]["value"] == "bold"
    overrides_by_key = {v["key"]: v["value"] for v in got["overrides"]}
    override_colors_children = {
        c["key"]: c["value"] for c in overrides_by_key["colors"]["children"]
    }
    assert override_colors_children["primary"]["value"] == "#ff00ff"


def _create_app(ctx):
    import time

    from botocore.exceptions import ClientError

    amplify = ctx.client("amplify")
    app_name = ctx.unique_name("sim2real-uib-")
    import random

    for attempt in range(20):
        try:
            resp = amplify.create_app(name=app_name)
            app_id = resp["app"]["appId"]
            ctx.on_cleanup(lambda: amplify.delete_app(appId=app_id))
            return app_id
        except ClientError as e:
            if "Rate exceeded" in str(e) and attempt < 19:
                time.sleep(min(30, 2**attempt) + random.uniform(0, 10))
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
