"""get-app-not-found-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-app-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["amplify"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetApp on a well-formed but nonexistent appId is rejected; a real app is still readable."""
    amplify = ctx.client("amplify")

    bogus_app_id = "dnonexistent00000000"
    err = _client_error(lambda: amplify.get_app(appId=bogus_app_id))
    assert err == ("NotFoundException", f"App {bogus_app_id} not found."), err

    # Positive control: a real app is fetched successfully in the same file.
    name = ctx.unique_name("sim2real-amplify-app-")
    app = amplify.create_app(name=name, tags={"sim2real-check": CHECK})["app"]
    ctx.on_cleanup(lambda: _ignore(lambda: amplify.delete_app(appId=app["appId"])))

    fetched = amplify.get_app(appId=app["appId"])["app"]
    assert fetched["name"] == name, f"expected name {name!r}, got {fetched['name']!r}"


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
