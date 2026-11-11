"""create-component-collection-properties-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-component-collection-properties-roundtrip"
GROUP = "lifecycle"
SERVICES = ["amplifyuibuilder"]

_ENV = "staging"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Collection component's collectionProperties (data model binding, sort order, filter
    predicate, and explicit identifiers) round-trips exactly through CreateComponent and
    GetComponent."""
    app_id = _create_app(ctx)
    uib = ctx.client("amplifyuibuilder")
    name = ctx.unique_name("sim2real-coll-").replace("-", "")
    name = name[0].upper() + name[1:]

    component_to_create = {
        "name": name,
        "componentType": "Collection",
        "properties": {},
        "variants": [],
        "overrides": {},
        "bindingProperties": {},
        "tags": {"sim2real": "true"},
        "collectionProperties": {
            "items": {
                "model": "Post",
                "sort": [{"field": "title", "direction": "ASC"}],
                "predicate": {"field": "status", "operator": "eq", "operand": "published"},
                "identifiers": ["id"],
            }
        },
    }

    created = uib.create_component(
        appId=app_id, environmentName=_ENV, componentToCreate=component_to_create
    )["entity"]
    comp_id = created["id"]
    ctx.on_cleanup(lambda: uib.delete_component(appId=app_id, environmentName=_ENV, id=comp_id))

    got = uib.get_component(appId=app_id, environmentName=_ENV, id=comp_id)["component"]
    items = got["collectionProperties"]["items"]
    assert items["model"] == "Post", f"expected model 'Post', got {items['model']!r}"
    assert items["sort"] == [{"field": "title", "direction": "ASC"}], (
        f"expected sort [{{'field': 'title', 'direction': 'ASC'}}], got {items['sort']!r}"
    )
    assert items["predicate"] == {
        "field": "status",
        "operator": "eq",
        "operand": "published",
    }, f"expected predicate field/operator/operand round-trip, got {items['predicate']!r}"
    assert items["identifiers"] == ["id"], f"expected identifiers ['id'], got {items['identifiers']!r}"


def _create_app(ctx):
    import random
    import time

    from botocore.exceptions import ClientError

    amplify = ctx.client("amplify")
    app_name = ctx.unique_name("sim2real-uib-")

    for attempt in range(20):
        try:
            resp = amplify.create_app(name=app_name, tags={"sim2real": "true"})
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
