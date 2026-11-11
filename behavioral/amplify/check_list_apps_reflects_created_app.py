"""list-apps-reflects-created-app."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-apps-reflects-created-app"
GROUP = "state"
SERVICES = ["amplify"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created app shows up in ListApps, paginated across the account's full app set,
    and GetApp rejects it with NotFoundException once deleted."""
    amplify = ctx.client("amplify")
    name = ctx.unique_name("sim2real-amplify-app-")
    app = amplify.create_app(name=name)["app"]
    app_id = app["appId"]
    ctx.on_cleanup(lambda: _ignore(lambda: amplify.delete_app(appId=app_id)))

    found = None
    token = None
    pages_left = 50
    while pages_left > 0:
        kwargs = {"maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        page = amplify.list_apps(**kwargs)
        for a in page["apps"]:
            if a["appId"] == app_id:
                found = a
                break
        if found is not None:
            break
        token = page.get("nextToken")
        if not token:
            break
        pages_left -= 1

    assert found is not None, f"app {app_id} not found in ListApps"
    assert found["name"] == name, f"expected name {name!r}, got {found['name']!r}"

    amplify.delete_app(appId=app_id)
    err = _client_error(lambda: amplify.get_app(appId=app_id))
    expected = ("NotFoundException", f"App {app_id} not found.")
    assert err == expected, f"expected {expected} after delete, got {err}"


def _ignore(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _client_error(fn) -> tuple[str, str]:
    """Call fn() and return its (code, message); an unexpected success raises, so an emulator
    accepting a call real AWS refuses never reads as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected a ClientError, call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
