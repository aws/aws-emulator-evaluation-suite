"""delete-form-state-transition-then-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-form-state-transition-then-not-found"
GROUP = "lifecycle"
SERVICES = ["amplifyuibuilder"]

_ENV = "staging"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteForm removes a form: GetForm succeeds before the delete, and GetForm and UpdateForm fail
    right after with a bare HTTP 404 (Code "404", not the modeled ResourceNotFoundException) and a
    not-found message."""
    app_id = _create_app(ctx)
    uib = ctx.client("amplifyuibuilder")
    name = ctx.unique_name("sim2real-delform-").replace("-", "")
    name = name[0].upper() + name[1:]

    created = uib.create_form(
        appId=app_id,
        environmentName=_ENV,
        formToCreate={
            "name": name,
            "dataType": {"dataSourceType": "DataStore", "dataTypeName": "Post"},
            "formActionType": "create",
            "fields": {},
            "style": {},
            "sectionalElements": {},
            "schemaVersion": "1.0",
            "tags": {"sim2real:managed": "true"},
        },
    )["entity"]
    form_id = created["id"]

    before = uib.get_form(appId=app_id, environmentName=_ENV, id=form_id)["form"]
    assert before["id"] == form_id, f"expected GetForm to echo id {form_id!r}, got {before['id']!r}"

    uib.delete_form(appId=app_id, environmentName=_ENV, id=form_id)

    error = _error_code(lambda: uib.get_form(appId=app_id, environmentName=_ENV, id=form_id))
    assert error["Code"] == "404", (
        "expected GetForm on a deleted form to raise Code '404' (amplifyuibuilder does not "
        f"surface ResourceNotFoundException here), got {error!r}"
    )
    assert "not found" in error.get("Message", "").lower(), (
        f"expected a not-found message on the post-delete GetForm, got {error!r}"
    )

    update_error = _error_code(
        lambda: uib.update_form(
            appId=app_id,
            environmentName=_ENV,
            id=form_id,
            updatedForm={"name": name},
        )
    )
    assert update_error["Code"] == "404", (
        f"expected UpdateForm on a deleted form to raise Code '404', got {update_error!r}"
    )
    assert "not found" in update_error.get("Message", "").lower(), (
        f"expected a not-found message on the post-delete UpdateForm, got {update_error!r}"
    )


def _create_app(ctx):
    import time

    from botocore.exceptions import ClientError

    import random

    amplify = ctx.client("amplify")
    app_name = ctx.unique_name("sim2real-uib-")
    for attempt in range(20):
        try:
            resp = amplify.create_app(name=app_name, tags={"sim2real:managed": "true"})
            app_id = resp["app"]["appId"]
            ctx.on_cleanup(lambda: amplify.delete_app(appId=app_id))
            return app_id
        except ClientError as e:
            if "Rate exceeded" in str(e) and attempt < 19:
                time.sleep(min(30, 2**attempt) + random.uniform(0, 10))
                continue
            raise


def _error_code(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises, so an accepted
    call is reported as accepted rather than as a wrong error code."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected this call to raise, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
