"""delete-theme-state-transition-then-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-theme-state-transition-then-not-found"
GROUP = "lifecycle"
SERVICES = ["amplifyuibuilder"]

_ENV = "staging"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTheme removes a theme: GetTheme succeeds before the delete, and GetTheme and UpdateTheme fail
    right after with a bare HTTP 404 (Code "404") and a not-found message: the error body carries no
    exception type, so botocore cannot map it to the modeled ResourceNotFoundException."""
    app_id = _create_app(ctx)
    uib = ctx.client("amplifyuibuilder")
    name = ctx.unique_name("sim2real-deltheme-").replace("-", "")
    name = name[0].upper() + name[1:]

    created = uib.create_theme(
        appId=app_id,
        environmentName=_ENV,
        themeToCreate={
            "name": name,
            "values": [
                {
                    "key": "colors",
                    "value": {
                        "children": [
                            {
                                "key": "font",
                                "value": {
                                    "children": [
                                        {"key": "primary", "value": {"value": "#000000"}}
                                    ]
                                },
                            }
                        ]
                    },
                }
            ],
            "tags": {"owner": "sim2real"},
        },
    )["entity"]
    theme_id = created["id"]

    before = uib.get_theme(appId=app_id, environmentName=_ENV, id=theme_id)["theme"]
    assert before["id"] == theme_id, f"expected id {theme_id} before delete, got {before['id']}"

    uib.delete_theme(appId=app_id, environmentName=_ENV, id=theme_id)

    code, message = _error_detail(
        lambda: uib.get_theme(appId=app_id, environmentName=_ENV, id=theme_id)
    )
    assert code == "404", f"expected the not-found HTTP status as the error code on GetTheme after delete, got {code!r}"
    assert "not found" in message.lower(), f"expected a not-found message on GetTheme after delete, got {message!r}"

    update_code, update_message = _error_detail(
        lambda: uib.update_theme(
            appId=app_id,
            environmentName=_ENV,
            id=theme_id,
            updatedTheme={
                "name": name,
                "values": [
                    {
                        "key": "colors",
                        "value": {
                            "children": [
                                {
                                    "key": "font",
                                    "value": {
                                        "children": [
                                            {"key": "primary", "value": {"value": "#ffffff"}}
                                        ]
                                    },
                                }
                            ]
                        },
                    }
                ],
            },
        )
    )
    assert update_code == "404", (
        f"expected UpdateTheme on the deleted id to also fail with the not-found HTTP status, got {update_code!r}"
    )
    assert "not found" in update_message.lower(), (
        f"expected a not-found message on UpdateTheme against the deleted id, got {update_message!r}"
    )


def _create_app(ctx):
    import time

    from botocore.exceptions import ClientError

    amplify = ctx.client("amplify")
    app_name = ctx.unique_name("sim2real-uib-")
    import random

    for attempt in range(20):
        try:
            resp = amplify.create_app(name=app_name, tags={"owner": "sim2real"})
            app_id = resp["app"]["appId"]
            ctx.on_cleanup(lambda: amplify.delete_app(appId=app_id))
            return app_id
        except ClientError as e:
            if "Rate exceeded" in str(e) and attempt < 19:
                time.sleep(min(30, 2**attempt) + random.uniform(0, 10))
                continue
            raise


def _error_detail(fn):
    try:
        fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
