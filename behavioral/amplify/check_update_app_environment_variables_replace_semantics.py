"""update-app-environment-variables-replace-semantics."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-app-environment-variables-replace-semantics"
GROUP = "state"
SERVICES = ["amplify"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateApp replaces the entire environmentVariables map rather than merging it."""
    amplify = ctx.client("amplify")
    name = ctx.unique_name("sim2real-amplify-app-")
    app = amplify.create_app(
        name=name,
        environmentVariables={"A": "1", "B": "2"},
        tags={"sim2real-check": "update-app-environment-variables-replace-semantics"},
    )["app"]
    app_id = app["appId"]
    ctx.on_cleanup(lambda: _ignore(lambda: amplify.delete_app(appId=app_id)))
    assert app["environmentVariables"] == {"A": "1", "B": "2"}, (
        f"expected create_app to echo {{'A': '1', 'B': '2'}}, got {app['environmentVariables']!r}"
    )

    updated = amplify.update_app(appId=app_id, environmentVariables={"C": "3"})["app"]
    assert updated["environmentVariables"] == {"C": "3"}, (
        f"expected update_app response to report only {{'C': '3'}}, got {updated['environmentVariables']!r}"
    )

    fetched = amplify.get_app(appId=app_id)["app"]
    assert fetched["environmentVariables"] == {"C": "3"}, (
        f"expected get_app to reflect the replaced map {{'C': '3'}}, got {fetched['environmentVariables']!r}"
    )
    assert "A" not in fetched["environmentVariables"], (
        f"expected 'A' to be gone after replace, but it is still present: {fetched['environmentVariables']!r}"
    )
    assert "B" not in fetched["environmentVariables"], (
        f"expected 'B' to be gone after replace, but it is still present: {fetched['environmentVariables']!r}"
    )


def _ignore(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
