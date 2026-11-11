"""export-components-matches-created-set."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "export-components-matches-created-set"
GROUP = "listing"
SERVICES = ["amplifyuibuilder"]

_ENV = "staging"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ExportComponents returns full Component objects (not just summaries) for every
    component created in the app/environment, matching the properties set at creation time."""
    app_id = _create_app(ctx)
    uib = ctx.client("amplifyuibuilder")
    name = ctx.unique_name("sim2real-export-").replace("-", "")
    name = name[0].upper() + name[1:]

    created = uib.create_component(
        appId=app_id,
        environmentName=_ENV,
        componentToCreate={
            "name": name,
            "componentType": "Button",
            "properties": {"label": {"value": "Click me"}},
            "variants": [],
            "overrides": {},
            "bindingProperties": {},
            "tags": {"sim2real": name},
        },
    )["entity"]
    comp_id = created["id"]
    ctx.on_cleanup(lambda: uib.delete_component(appId=app_id, environmentName=_ENV, id=comp_id))

    exported = []
    token = None
    while True:
        kwargs = {"appId": app_id, "environmentName": _ENV}
        if token:
            kwargs["nextToken"] = token
        resp = uib.export_components(**kwargs)
        exported.extend(resp.get("entities", []))
        token = resp.get("nextToken")
        if not token:
            break

    matches = [e for e in exported if e["id"] == comp_id]
    assert len(matches) == 1, (
        f"expected exactly 1 exported entity with id={comp_id!r}, found {len(matches)} "
        f"among {len(exported)} exported entities"
    )
    exported_component = matches[0]
    assert exported_component["name"] == name, (
        f"expected exported name {name!r}, got {exported_component['name']!r}"
    )
    assert exported_component["componentType"] == "Button", (
        f"expected exported componentType 'Button', got {exported_component['componentType']!r}"
    )
    assert exported_component["properties"]["label"]["value"] == "Click me", (
        f"expected exported properties.label.value 'Click me', got "
        f"{exported_component['properties']['label']['value']!r}"
    )


def _create_app(ctx):
    import time

    from botocore.exceptions import ClientError

    amplify = ctx.client("amplify")
    app_name = ctx.unique_name("sim2real-uib-")
    import random

    for attempt in range(20):
        try:
            resp = amplify.create_app(name=app_name, tags={"sim2real": app_name})
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
