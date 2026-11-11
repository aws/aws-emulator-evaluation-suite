"""get-component-cross-environment-isolation-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-component-cross-environment-isolation-rejected"
GROUP = "overly-permissive"
SERVICES = ["amplifyuibuilder"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A component is scoped to the app it was created under: GetComponent by its id under another app
    (same environmentName) fails with HTTP 400 (Code "400", no __type) saying the item does not belong
    to that app/environment, while the same call under the owning app succeeds."""
    app_id = _create_app(ctx)
    other_app_id = _create_app(ctx)
    uib = ctx.client("amplifyuibuilder")
    env = "staging"
    name = ctx.unique_name("sim2real-iso-").replace("-", "")
    name = name[0].upper() + name[1:]

    created = uib.create_component(
        appId=app_id,
        environmentName=env,
        componentToCreate={
            "name": name,
            "componentType": "Text",
            "properties": {"label": {"value": "scoped"}},
            "variants": [],
            "overrides": {},
            "bindingProperties": {},
        },
    )["entity"]
    comp_id = created["id"]
    ctx.on_cleanup(lambda: uib.delete_component(appId=app_id, environmentName=env, id=comp_id))

    try:
        uib.get_component(appId=other_app_id, environmentName=env, id=comp_id)
        raise AssertionError("expected the cross-app fetch to be rejected, but it succeeded")
    except ClientError as e:
        err = e.response["Error"]
        status = e.response["ResponseMetadata"]["HTTPStatusCode"]
        assert status == 400, f"expected HTTP 400, got {status} ({err})"
        assert err.get("Message") == "The item requests does not belong to that app or environment", (
            f"expected the cross-app-isolation message, got {err}"
        )

    # positive control: the correct app still resolves the component
    fetched = uib.get_component(appId=app_id, environmentName=env, id=comp_id)["component"]
    assert fetched["id"] == comp_id
    assert fetched["name"] == name


def _create_app(ctx):
    import time

    from botocore.exceptions import ClientError

    amplify = ctx.client("amplify")
    app_name = ctx.unique_name("sim2real-uib-")
    import random

    time.sleep(random.uniform(0, 10))
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
