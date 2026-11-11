"""delete-component-nonexistent-id-not-found-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-component-nonexistent-id-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["amplifyuibuilder"]

_ENV = "staging"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteComponent on a never-created id is refused with a bare HTTP 404 and the exact message
    and leaves a sibling component untouched; deleting the sibling succeeds, after which
    GetComponent answers 404 with its exact message."""
    app_id = _create_app(ctx)
    uib = ctx.client("amplifyuibuilder")
    name = ctx.unique_name("sim2real-delc-").replace("-", "")
    name = name[0].upper() + name[1:]
    real = uib.create_component(
        appId=app_id,
        environmentName=_ENV,
        componentToCreate={
            "name": name,
            "componentType": "Text",
            "properties": {"label": {"value": "alive"}},
            "variants": [],
            "overrides": {},
            "bindingProperties": {},
            "tags": {"sim2real": CHECK},
        },
    )["entity"]
    real_id = real["id"]

    missing_id = str(uuid.uuid4())
    err = _error(
        lambda: uib.delete_component(appId=app_id, environmentName=_ENV, id=missing_id)
    )
    assert err["Code"] == "404", (
        f"expected DeleteComponent on a never-created id to be rejected with botocore code "
        f"'404' (real AWS answers a bare HTTP 404, not a modeled exception type), "
        f"got {err!r}"
    )
    assert err.get("Message") == "Unable to find item to delete", (
        f"expected the exact not-found message, got {err!r}"
    )

    # effect absent: the real component was not affected by the failed delete
    still_there = uib.get_component(appId=app_id, environmentName=_ENV, id=real_id)["component"]
    assert still_there["id"] == real_id, (
        f"expected real component {real_id!r} untouched by the rejected delete, "
        f"got {still_there['id']!r}"
    )

    # positive control: deleting the real component succeeds and it disappears
    uib.delete_component(appId=app_id, environmentName=_ENV, id=real_id)
    get_err = _error(
        lambda: uib.get_component(appId=app_id, environmentName=_ENV, id=real_id)
    )
    assert get_err["Code"] == "404", (
        f"expected GetComponent on the just-deleted real id {real_id!r} to be rejected with "
        f"botocore code '404', got {get_err!r}"
    )
    assert get_err.get("Message") == "The item specified was not found", (
        f"expected the exact not-found message, got {get_err!r}"
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
    """Call fn(); return its botocore Error dict. A success raises: accepting a call AWS refuses is a
    mismatch of its own, not a wrong error code."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
