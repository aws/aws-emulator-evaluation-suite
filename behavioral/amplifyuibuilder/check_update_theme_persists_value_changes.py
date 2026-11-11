"""update-theme-persists-value-changes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-theme-persists-value-changes"
GROUP = "lifecycle"
SERVICES = ["amplifyuibuilder"]

_ENV = "staging"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTheme persists a changed value and GetTheme reflects the new value afterwards."""
    app_id = _create_app(ctx)
    uib = ctx.client("amplifyuibuilder")
    name = ctx.unique_name("sim2real-updtheme-").replace("-", "")
    name = name[0].upper() + name[1:]

    created = uib.create_theme(
        appId=app_id,
        environmentName=_ENV,
        themeToCreate={
            "name": name,
            "values": [
                {
                    "key": "colors",
                    "value": {
                        "children": [
                            {
                                "key": "font",
                                "value": {
                                    "children": [
                                        {"key": "primary", "value": {"value": "#0000ff"}}
                                    ]
                                },
                            }
                        ]
                    },
                }
            ],
            "tags": {"sim2real": "check_update_theme_persists_value_changes"},
        },
    )["entity"]
    theme_id = created["id"]
    ctx.on_cleanup(lambda: uib.delete_theme(appId=app_id, environmentName=_ENV, id=theme_id))

    updated = uib.update_theme(
        appId=app_id,
        environmentName=_ENV,
        id=theme_id,
        updatedTheme={
            "name": name,
            "values": [
                {
                    "key": "colors",
                    "value": {
                        "children": [
                            {
                                "key": "font",
                                "value": {
                                    "children": [
                                        {"key": "primary", "value": {"value": "#00ff00"}}
                                    ]
                                },
                            }
                        ]
                    },
                }
            ],
        },
    )["entity"]

    def _dig(values):
        by_key = {v["key"]: v["value"] for v in values}
        font_children = {c["key"]: c["value"] for c in by_key["colors"]["children"]}
        primary_children = {c["key"]: c["value"] for c in font_children["font"]["children"]}
        return primary_children["primary"]["value"]

    updated_value = _dig(updated["values"])
    assert updated_value == "#00ff00", f"expected #00ff00 from UpdateTheme, got {updated_value!r}"

    fetched = uib.get_theme(appId=app_id, environmentName=_ENV, id=theme_id)["theme"]
    fetched_value = _dig(fetched["values"])
    assert fetched_value == "#00ff00", f"expected #00ff00 from GetTheme, got {fetched_value!r}"


def _create_app(ctx):
    import random
    import time

    from botocore.exceptions import ClientError

    amplify = ctx.client("amplify")
    app_name = ctx.unique_name("sim2real-uib-")
    for attempt in range(20):
        try:
            resp = amplify.create_app(
                name=app_name,
                tags={"sim2real": "check_update_theme_persists_value_changes"},
            )
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
