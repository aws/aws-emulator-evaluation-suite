"""create-component-roundtrip-nested-properties."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-component-roundtrip-nested-properties"
GROUP = "lifecycle"
SERVICES = ["amplifyuibuilder"]

_ENV = "staging"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateComponent persists a fully-populated component (properties, variants, overrides,
    data bindings, children, and events) and GetComponent returns the exact same nested
    structure back."""
    app_id = _create_app(ctx)
    uib = ctx.client("amplifyuibuilder")
    name = ctx.unique_name("sim2real-comp-").replace("-", "")
    name = name[0].upper() + name[1:]

    component_to_create = {
        "name": name,
        "componentType": "Text",
        "properties": {"label": {"value": "Hello World"}},
        "variants": [
            {
                "variantValues": {"platform": "web"},
                "overrides": {"button-1": {"type": "style", "value": "red"}},
            }
        ],
        "overrides": {"button-1": {"type": "style", "value": "green"}},
        "bindingProperties": {
            "label": {
                "type": "String",
                "bindingProperties": {"field": "title", "model": "Post"},
                "defaultValue": "untitled",
            }
        },
        "children": [
            {
                "componentType": "Text",
                "name": "childText",
                "properties": {"label": {"value": "child-value"}},
            }
        ],
        "events": {
            "onClick": {
                "action": "navigate",
                "bindingEvent": "click",
                "parameters": {
                    "type": {"value": "url"},
                    "url": {"value": "https://example.com"},
                },
            }
        },
        "tags": {"sim2real": CHECK},
    }

    created = uib.create_component(
        appId=app_id, environmentName=_ENV, componentToCreate=component_to_create
    )["entity"]
    comp_id = created["id"]
    ctx.on_cleanup(lambda: uib.delete_component(appId=app_id, environmentName=_ENV, id=comp_id))

    got = uib.get_component(appId=app_id, environmentName=_ENV, id=comp_id)["component"]

    assert got["name"] == name, f"expected name {name!r}, got {got['name']!r}"
    assert got["componentType"] == "Text", (
        f"expected componentType 'Text', got {got['componentType']!r}"
    )
    assert got["properties"]["label"]["value"] == "Hello World", (
        f"expected properties.label.value 'Hello World', got "
        f"{got['properties']['label'].get('value')!r}"
    )
    assert got["variants"][0]["variantValues"] == {"platform": "web"}, (
        f"expected variants[0].variantValues {{'platform': 'web'}}, got "
        f"{got['variants'][0].get('variantValues')!r}"
    )
    assert got["variants"][0]["overrides"]["button-1"] == {"type": "style", "value": "red"}, (
        f"expected variants[0].overrides['button-1'] "
        f"{{'type': 'style', 'value': 'red'}}, got "
        f"{got['variants'][0]['overrides'].get('button-1')!r}"
    )
    assert got["overrides"]["button-1"] == {"type": "style", "value": "green"}, (
        f"expected overrides['button-1'] {{'type': 'style', 'value': 'green'}}, got "
        f"{got['overrides'].get('button-1')!r}"
    )
    assert got["bindingProperties"]["label"]["bindingProperties"]["field"] == "title", (
        f"expected bindingProperties.label.bindingProperties.field 'title', got "
        f"{got['bindingProperties']['label']['bindingProperties'].get('field')!r}"
    )
    assert got["bindingProperties"]["label"]["bindingProperties"]["model"] == "Post", (
        f"expected bindingProperties.label.bindingProperties.model 'Post', got "
        f"{got['bindingProperties']['label']['bindingProperties'].get('model')!r}"
    )
    assert got["bindingProperties"]["label"]["defaultValue"] == "untitled", (
        f"expected bindingProperties.label.defaultValue 'untitled', got "
        f"{got['bindingProperties']['label'].get('defaultValue')!r}"
    )
    assert len(got["children"]) == 1, f"expected exactly 1 child, got {len(got['children'])}"
    assert got["children"][0]["name"] == "childText", (
        f"expected children[0].name 'childText', got {got['children'][0].get('name')!r}"
    )
    assert got["children"][0]["properties"]["label"]["value"] == "child-value", (
        f"expected children[0].properties.label.value 'child-value', got "
        f"{got['children'][0]['properties']['label'].get('value')!r}"
    )
    assert got["events"]["onClick"]["action"] == "navigate", (
        f"expected events.onClick.action 'navigate', got "
        f"{got['events']['onClick'].get('action')!r}"
    )
    assert got["events"]["onClick"]["parameters"]["url"]["value"] == "https://example.com", (
        f"expected events.onClick.parameters.url.value 'https://example.com', got "
        f"{got['events']['onClick']['parameters']['url'].get('value')!r}"
    )


def _create_app(ctx):
    import random
    import time

    from botocore.exceptions import ClientError

    amplify = ctx.client("amplify")
    app_name = ctx.unique_name("sim2real-uib-")

    for attempt in range(20):
        try:
            resp = amplify.create_app(name=app_name, tags={"sim2real": CHECK})
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
