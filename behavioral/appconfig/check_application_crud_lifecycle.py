"""application-crud-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "application-crud-lifecycle"
GROUP = 'application'
SERVICES = ['appconfig']

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-application-crud-lifecycle"}


def _error(fn):
    """Return the botocore (Error.Code, HTTP status, Error.Message) if fn() raises ClientError.

    Raises on unexpected SUCCESS rather than returning a falsy sentinel: an emulator that
    accepts a call real AWS refuses is the strongest signal available, and returning None
    would turn that into an error-code mismatch that reads like a naming difference.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), status, err.get("Message") or ""
    raise AssertionError(
        f"the call under test SUCCEEDED where real AWS refuses it, returning {result!r} — this "
        "is an over-permissiveness failure, not an error-code mismatch"
    )


def _delete_application_if_present(ac, app_id):
    """Teardown: the check deletes the application itself, so an absent one is the expected end."""
    try:
        ac.delete_application(ApplicationId=app_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Application create->get->update->delete->get(404) state machine holds; a second delete
    against the dead id fails with the same not-found code rather than being silently accepted."""
    ac = ctx.client("appconfig")
    name = ctx.unique_name("sim2real-behav-app-")
    created = ac.create_application(Name=name, Description="initial description", Tags=_TAGS)
    app_id = created["Id"]
    ctx.on_cleanup(lambda: _delete_application_if_present(ac, app_id))
    assert created["Name"] == name, f"expected created Name {name!r}, got {created['Name']!r}"

    got = ac.get_application(ApplicationId=app_id)
    assert got["Id"] == app_id, f"expected Id {app_id!r}, got {got['Id']!r}"
    assert got["Name"] == name, f"expected Name {name!r}, got {got['Name']!r}"
    assert got["Description"] == "initial description", (
        f"expected Description 'initial description', got {got['Description']!r}"
    )

    updated = ac.update_application(ApplicationId=app_id, Description="updated description")
    assert updated["Description"] == "updated description", (
        f"expected updated Description 'updated description', got {updated['Description']!r}"
    )

    got_after_update = ac.get_application(ApplicationId=app_id)
    assert got_after_update["Description"] == "updated description", (
        f"expected persisted Description 'updated description', got "
        f"{got_after_update['Description']!r}"
    )
    # Name unaffected by an update that only touches Description.
    assert got_after_update["Name"] == name, (
        f"expected Name unaffected by a Description-only update, got {got_after_update['Name']!r}"
    )

    def _listed_ids():
        return [
            a["Id"]
            for page in ac.get_paginator("list_applications").paginate()
            for a in page.get("Items", [])
        ]

    assert app_id in _listed_ids(), f"live application {app_id!r} is not listed by ListApplications"

    ac.delete_application(ApplicationId=app_id)

    def _assert_not_found(label, fn):
        code, status, message = _error(fn)
        assert code == "ResourceNotFoundException", f"{label}: expected ResourceNotFoundException, got {code!r}"
        assert isinstance(status, int) and 400 <= status < 500, f"{label}: expected HTTP 4xx, got {status!r}"
        expected_message = f"Application with Id {app_id} could not be found for account {ctx.account}."
        assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    _assert_not_found("GetApplication after delete", lambda: ac.get_application(ApplicationId=app_id))

    assert app_id not in _listed_ids(), f"deleted application {app_id!r} is still listed by ListApplications"

    # Deletes prove unusable, not just gone: a mutation and a second delete against the dead id
    # fail with the same specific code rather than being silently accepted or misclassified.
    code, status, message = _error(lambda: ac.update_application(ApplicationId=app_id, Description="x"))
    assert code == "ResourceNotFoundException", (
        f"UpdateApplication after delete: expected ResourceNotFoundException, got {code!r}"
    )
    assert isinstance(status, int) and 400 <= status < 500, f"UpdateApplication after delete: expected HTTP 4xx, got {status!r}"
    expected_message = f"Application with Id {app_id} could not be found for account {ctx.account}."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"
    _assert_not_found("second DeleteApplication", lambda: ac.delete_application(ApplicationId=app_id))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
