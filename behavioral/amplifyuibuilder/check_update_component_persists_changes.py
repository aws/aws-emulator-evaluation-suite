"""update-component-persists-changes."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-component-persists-changes"
GROUP = "lifecycle"
SERVICES = ["amplifyuibuilder"]

_ENV = "staging"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateComponent persists new property/name values and GetComponent reflects them
    afterwards."""
    app_id = _create_app(ctx)
    uib = ctx.client("amplifyuibuilder")
    name = ctx.unique_name("sim2real-comp-").replace("-", "")
    name = name[0].upper() + name[1:]
    created = uib.create_component(
        appId=app_id,
        environmentName=_ENV,
        componentToCreate={
            "name": name,
            "componentType": "Text",
            "properties": {"label": {"value": "before"}},
            "variants": [],
            "overrides": {},
            "bindingProperties": {},
            "tags": {"sim2real": CHECK},
        },
    )["entity"]
    comp_id = created["id"]
    ctx.on_cleanup(lambda: uib.delete_component(appId=app_id, environmentName=_ENV, id=comp_id))

    new_name = name + "Renamed"
    updated = uib.update_component(
        appId=app_id,
        environmentName=_ENV,
        id=comp_id,
        updatedComponent={
            "id": comp_id,
            "name": new_name,
            "componentType": "Text",
            "properties": {"label": {"value": "after"}},
            "variants": [],
            "overrides": {},
            "bindingProperties": {},
        },
    )["entity"]
    assert updated["name"] == new_name, f"expected name {new_name!r}, got {updated['name']!r}"
    assert updated["properties"]["label"]["value"] == "after", (
        f"expected properties.label.value 'after', got "
        f"{updated['properties']['label'].get('value')!r}"
    )

    # Poll for the update to be durably reflected (modifiedAt strictly newer than createdAt)
    # rather than sleeping a fixed duration -- avoids both flakiness on a slow backend and
    # paying a fixed delay on a fast one.
    fetched = _poll_until(
        lambda: uib.get_component(appId=app_id, environmentName=_ENV, id=comp_id)["component"],
        lambda c: c["name"] == new_name and c["modifiedAt"] > c["createdAt"],
        timeout_s=30,
        interval_s=1,
    )
    assert fetched["name"] == new_name, f"expected name {new_name!r}, got {fetched['name']!r}"
    assert fetched["properties"]["label"]["value"] == "after", (
        f"expected properties.label.value 'after', got "
        f"{fetched['properties']['label'].get('value')!r}"
    )
    assert fetched["modifiedAt"] > fetched["createdAt"], (
        f"expected modifiedAt {fetched['modifiedAt']!r} > createdAt "
        f"{fetched['createdAt']!r} after update"
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


def _poll_until(probe, predicate, *, timeout_s=30, interval_s=1):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last value: {result!r}")
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
