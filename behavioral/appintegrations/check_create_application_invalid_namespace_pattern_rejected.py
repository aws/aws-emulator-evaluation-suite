"""create-application-invalid-namespace-pattern-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-application-invalid-namespace-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["appintegrations"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApplication rejects a Namespace containing characters outside the allowed pattern."""
    appi = ctx.client("appintegrations")
    bad_namespace = "invalid namespace!"  # spaces and '!' are not in ^[a-zA-Z0-9/._-]+$
    good_namespace = ctx.unique_name("sim2real-ns-valid-")
    name = ctx.unique_name("sim2real-app-pattern-")

    code, message = _client_error(
        lambda: appi.create_application(
            Name=name,
            Namespace=bad_namespace,
            ApplicationSourceConfig={
                "ExternalUrlConfig": {"AccessUrl": "https://example.com/bad"}
            },
        )
    )
    assert code == "BadRequestException", code
    expected_message = "Invalid request body"
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # Positive control: same call shape with a valid Namespace succeeds.
    created = appi.create_application(
        Name=name,
        Namespace=good_namespace,
        ApplicationSourceConfig={
            "ExternalUrlConfig": {"AccessUrl": "https://example.com/good"}
        },
    )
    arn = created["Arn"]
    ctx.on_cleanup(lambda: appi.delete_application(Arn=arn))
    got = appi.get_application(Arn=arn)
    assert got["Namespace"] == good_namespace, f"expected Namespace {good_namespace!r}, got {got.get('Namespace')!r}"


def _client_error(fn: Any) -> tuple[str, str]:
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
