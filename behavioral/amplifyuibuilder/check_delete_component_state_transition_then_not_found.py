"""delete-component-state-transition-then-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-component-state-transition-then-not-found"
GROUP = "lifecycle"
SERVICES = ["amplifyuibuilder"]

_ENV = "staging"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteComponent removes a component: GetComponent succeeds before the delete and fails right after
    with HTTP 404 "The item specified was not found" (Code "404": the error body carries no __type)."""
    app_id = _create_app(ctx)
    uib = ctx.client("amplifyuibuilder")
    name = ctx.unique_name("sim2real-delstate-").replace("-", "")
    name = name[0].upper() + name[1:]

    created = uib.create_component(
        appId=app_id,
        environmentName=_ENV,
        componentToCreate={
            "name": name,
            "componentType": "Text",
            "properties": {"label": {"value": "x"}},
            "variants": [],
            "overrides": {},
            "bindingProperties": {},
        },
    )["entity"]
    comp_id = created["id"]

    before = uib.get_component(appId=app_id, environmentName=_ENV, id=comp_id)["component"]
    assert before["id"] == comp_id, f"expected component {comp_id} to exist before delete, got {before!r}"

    uib.delete_component(appId=app_id, environmentName=_ENV, id=comp_id)

    try:
        uib.get_component(appId=app_id, environmentName=_ENV, id=comp_id)
        raise AssertionError("expected GetComponent on a deleted id to fail, but it succeeded")
    except ClientError as e:
        err = e.response["Error"]
        status = e.response["ResponseMetadata"]["HTTPStatusCode"]
        assert status == 404, f"expected HTTP 404, got {status} ({err})"
        assert err.get("Message") == "The item specified was not found", (
            f"expected the not-found message, got {err}"
        )


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
