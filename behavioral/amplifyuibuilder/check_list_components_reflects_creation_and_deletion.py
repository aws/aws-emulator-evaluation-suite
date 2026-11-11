"""list-components-reflects-creation-and-deletion."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-components-reflects-creation-and-deletion"
GROUP = "listing"
SERVICES = ["amplifyuibuilder"]

_ENV = "staging"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListComponents reflects both components right after creation, and reflects the removal
    of one after DeleteComponent while the sibling remains listed."""
    app_id = _create_app(ctx)
    uib = ctx.client("amplifyuibuilder")
    name1 = ctx.unique_name("sim2real-lst1-").replace("-", "")
    name1 = name1[0].upper() + name1[1:]
    name2 = ctx.unique_name("sim2real-lst2-").replace("-", "")
    name2 = name2[0].upper() + name2[1:]

    def _make(component_name):
        return uib.create_component(
            appId=app_id,
            environmentName=_ENV,
            componentToCreate={
                "name": component_name,
                "componentType": "Text",
                "properties": {},
                "variants": [],
                "overrides": {},
                "bindingProperties": {},
                "tags": {"owner": "sim2real"},
            },
        )["entity"]

    comp1 = _make(name1)
    comp2 = _make(name2)
    ctx.on_cleanup(lambda: uib.delete_component(appId=app_id, environmentName=_ENV, id=comp2["id"]))

    names_after_create = {e["name"] for e in _list_all(uib, app_id)}
    assert name1 in names_after_create, f"expected {name1} in ListComponents, got {names_after_create}"
    assert name2 in names_after_create, f"expected {name2} in ListComponents, got {names_after_create}"

    uib.delete_component(appId=app_id, environmentName=_ENV, id=comp1["id"])

    names_after_delete = {e["name"] for e in _list_all(uib, app_id)}
    assert name1 not in names_after_delete, (
        f"expected {name1} absent from ListComponents after DeleteComponent, got {names_after_delete}"
    )
    assert name2 in names_after_delete, (
        f"expected surviving sibling {name2} still in ListComponents, got {names_after_delete}"
    )


def _create_app(ctx):
    import time

    from botocore.exceptions import ClientError

    amplify = ctx.client("amplify")
    app_name = ctx.unique_name("sim2real-uib-")
    import random

    for attempt in range(20):
        try:
            resp = amplify.create_app(name=app_name, tags={"owner": "sim2real"})
            app_id = resp["app"]["appId"]
            ctx.on_cleanup(lambda: amplify.delete_app(appId=app_id))
            return app_id
        except ClientError as e:
            if "Rate exceeded" in str(e) and attempt < 19:
                time.sleep(min(30, 2**attempt) + random.uniform(0, 10))
                continue
            raise


def _list_all(uib, app_id):
    items = []
    token = None
    while True:
        kwargs = {"appId": app_id, "environmentName": "staging"}
        if token:
            kwargs["nextToken"] = token
        resp = uib.list_components(**kwargs)
        items.extend(resp.get("entities", []))
        token = resp.get("nextToken")
        if not token:
            break
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
