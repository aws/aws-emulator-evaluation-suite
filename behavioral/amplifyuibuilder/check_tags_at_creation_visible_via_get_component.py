"""tags-at-creation-visible-via-get-component."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tags-at-creation-visible-via-get-component"
GROUP = "tagging"
SERVICES = ["amplifyuibuilder"]

_ENV = "staging"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags given in CreateComponentData.tags appear on the Component returned by CreateComponent and
    GetComponent, and GetComponent on the component fails with HTTP 404 once it is deleted."""
    app_id = _create_app(ctx)
    uib = ctx.client("amplifyuibuilder")
    name = ctx.unique_name("sim2real-cgtag-").replace("-", "")
    name = name[0].upper() + name[1:]
    expected_tags = {"owner": "sim2real", "sim2real": CHECK}

    created = uib.create_component(
        appId=app_id,
        environmentName=_ENV,
        componentToCreate={
            "name": name,
            "componentType": "Text",
            "properties": {},
            "variants": [],
            "overrides": {},
            "bindingProperties": {},
            "tags": expected_tags,
        },
    )["entity"]
    comp_id = created["id"]

    assert created.get("tags") == expected_tags, (
        f"expected CreateComponent's own response to echo the supplied tags exactly, "
        f"got {created.get('tags')!r}"
    )

    got = uib.get_component(appId=app_id, environmentName=_ENV, id=comp_id)["component"]
    assert got.get("tags") == expected_tags, (
        f"expected GetComponent (an independent read, not the create response) to surface "
        f"the same tags, got {got.get('tags')!r}"
    )

    # The deleted component is gone from the same read path that showed its tags.
    uib.delete_component(appId=app_id, environmentName=_ENV, id=comp_id)
    err = _error(lambda: uib.get_component(appId=app_id, environmentName=_ENV, id=comp_id))
    assert err["Code"] == "404", (
        f"expected GetComponent on the just-deleted component {comp_id!r} to be rejected with "
        f"botocore code '404', got {err!r}"
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


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises, so an accepted
    call is reported as accepted rather than as a wrong error code."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
