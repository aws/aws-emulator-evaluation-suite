"""create-component-duplicate-name-conflict-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-component-duplicate-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["amplifyuibuilder"]

_ENV = "staging"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second component with an already-used name is refused with HTTP 409 and the exact message
    and leaves the original untouched; a different name succeeds, and the same name succeeds once
    the original is deleted, so the conflict tracks live state."""
    app_id = _create_app(ctx)
    uib = ctx.client("amplifyuibuilder")
    name = ctx.unique_name("sim2real-dupe-").replace("-", "")
    name = name[0].upper() + name[1:]

    def _payload(component_name, label):
        return {
            "name": component_name,
            "componentType": "Text",
            "properties": {"label": {"value": label}},
            "variants": [],
            "overrides": {},
            "bindingProperties": {},
        }

    original = uib.create_component(
        appId=app_id, environmentName=_ENV, componentToCreate=_payload(name, "original")
    )["entity"]
    original_id = original["id"]
    ctx.on_cleanup(lambda: uib.delete_component(appId=app_id, environmentName=_ENV, id=original_id))

    # The error response carries no error-type discriminator, so botocore's Error.Code is the
    # bare HTTP status "409" rather than ResourceConflictException.
    code, message = _error_detail(
        lambda: uib.create_component(
            appId=app_id, environmentName=_ENV, componentToCreate=_payload(name, "duplicate")
        )
    )
    assert code == "409", (
        f"expected a second create with the already-used name {name!r} to be rejected with "
        f"HTTP 409, got Error.Code {code!r}"
    )
    assert message == "Item name already exists", (
        f"expected the rejection message to be 'Item name already exists', got {message!r}"
    )

    # effect absent: exactly one component with this name, unchanged from the original create
    still_there = uib.get_component(appId=app_id, environmentName=_ENV, id=original_id)["component"]
    assert still_there["properties"]["label"]["value"] == "original", (
        f"the rejected duplicate create changed the original component's label to "
        f"{still_there['properties']['label']['value']!r}, expected it to remain 'original'"
    )
    entities = uib.list_components(appId=app_id, environmentName=_ENV)["entities"]
    matching = sum(1 for e in entities if e["name"] == name)
    assert matching == 1, (
        f"expected exactly 1 component named {name!r} after the rejected duplicate create, "
        f"found {matching}"
    )

    # positive control: creating with a different name in the same app/environment succeeds
    other_name = ctx.unique_name("sim2real-dupe-ctrl-").replace("-", "")
    other_name = other_name[0].upper() + other_name[1:]
    control = uib.create_component(
        appId=app_id, environmentName=_ENV, componentToCreate=_payload(other_name, "control")
    )["entity"]
    ctx.on_cleanup(lambda: uib.delete_component(appId=app_id, environmentName=_ENV, id=control["id"]))
    assert control["name"] == other_name, (
        f"expected the control create to be named {other_name!r}, got {control['name']!r}"
    )

    # restore: the conflict is a live-state constraint, not a malformed input, so it must be
    # possible to free the name and have the identical call succeed. Delete the original, confirm
    # it is independently gone, then re-issue the exact same create call and demand success.
    uib.delete_component(appId=app_id, environmentName=_ENV, id=original_id)
    # Same discriminator-less error shape as the conflict above: GetComponent's not-found
    # response also carries no modeled error-type, so Error.Code is the bare HTTP status "404"
    # rather than ResourceNotFoundException -- confirmed against real AWS.
    gone_code, gone_message = _error_detail(
        lambda: uib.get_component(appId=app_id, environmentName=_ENV, id=original_id)
    )
    assert gone_code == "404", (
        f"expected the deleted original to read back HTTP 404, got Error.Code {gone_code!r}"
    )
    assert gone_message == "The item specified was not found", (
        f"expected the not-found message to be 'The item specified was not found', got "
        f"{gone_message!r}"
    )
    restored = uib.create_component(
        appId=app_id, environmentName=_ENV, componentToCreate=_payload(name, "restored")
    )["entity"]
    restored_id = restored["id"]
    ctx.on_cleanup(lambda: uib.delete_component(appId=app_id, environmentName=_ENV, id=restored_id))
    assert restored["name"] == name, (
        f"expected the name {name!r} to be creatable again after the original was deleted, got "
        f"{restored['name']!r}"
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


def _error_detail(fn):
    """Call fn(); return its (Code, Message). A success raises: accepting a call AWS refuses is a
    mismatch of its own, not a wrong error code."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _error_code(fn):
    return _error_detail(fn)[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
