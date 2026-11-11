"""update-component-nonexistent-id-conflict-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-component-nonexistent-id-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["amplifyuibuilder"]

_ENV = "staging"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateComponent and GetComponent on an id that was never created fail with an unmodeled bare
    HTTP 404 "The item specified was not found" (not the modeled ResourceConflictException or
    ResourceNotFoundException), while UpdateComponent on an existing component succeeds."""
    app_id = _create_app(ctx)
    uib = ctx.client("amplifyuibuilder")
    name = ctx.unique_name("sim2real-updc-").replace("-", "")
    name = name[0].upper() + name[1:]
    real = uib.create_component(
        appId=app_id,
        environmentName=_ENV,
        componentToCreate={
            "name": name,
            "componentType": "Text",
            "properties": {"label": {"value": "before"}},
            "variants": [],
            "overrides": {},
            "bindingProperties": {},
        },
    )["entity"]
    real_id = real["id"]
    ctx.on_cleanup(lambda: uib.delete_component(appId=app_id, environmentName=_ENV, id=real_id))

    missing_id = str(uuid.uuid4())
    _assert_unmodeled_not_found(
        lambda: uib.update_component(
            appId=app_id,
            environmentName=_ENV,
            id=missing_id,
            updatedComponent={"id": missing_id, "name": "Ghost"},
        ),
        "UpdateComponent",
    )

    # effect absent: no component was created at the missing id
    _assert_unmodeled_not_found(
        lambda: uib.get_component(appId=app_id, environmentName=_ENV, id=missing_id),
        "GetComponent",
    )

    # positive control: updating the real component succeeds, verified by an independent read
    uib.update_component(
        appId=app_id,
        environmentName=_ENV,
        id=real_id,
        updatedComponent={"id": real_id, "name": name, "properties": {"label": {"value": "after"}}},
    )
    fetched = uib.get_component(appId=app_id, environmentName=_ENV, id=real_id)["component"]
    assert fetched["properties"]["label"]["value"] == "after", (
        f'expected label "after", got {fetched["properties"]["label"]["value"]!r}'
    )


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


def _assert_unmodeled_not_found(fn, op_name):
    try:
        fn()
        raise AssertionError(f"expected {op_name} on the nonexistent id to be rejected, but it succeeded")
    except ClientError as e:
        status = e.response["ResponseMetadata"]["HTTPStatusCode"]
        message = e.response["Error"]["Message"]
        assert status == 404, f"{op_name}: expected HTTP 404, got {status}"
        assert message == "The item specified was not found", (
            f"{op_name}: expected the unmodeled not-found body, got {message!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
