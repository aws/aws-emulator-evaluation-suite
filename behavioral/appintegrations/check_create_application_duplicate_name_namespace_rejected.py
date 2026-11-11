"""create-application-duplicate-name-namespace-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-application-duplicate-name-namespace-rejected"
GROUP = "overly-permissive"
SERVICES = ["appintegrations"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateApplication with the same Name+Namespace is rejected while the original
    exists, the original is left untouched by the failed attempt, and the identical call succeeds
    once the conflicting original is removed."""
    appi = ctx.client("appintegrations")
    name = ctx.unique_name("sim2real-app-dup-")
    namespace = ctx.unique_name("sim2real-ns-dup-")

    created = appi.create_application(
        Name=name,
        Namespace=namespace,
        Description="original",
        ApplicationSourceConfig={
            "ExternalUrlConfig": {"AccessUrl": "https://example.com/original"}
        },
    )
    arn = created["Arn"]
    live_arn = {"value": arn}

    def _cleanup() -> None:
        try:
            appi.delete_application(Arn=live_arn["value"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    code, message = _client_error(
        lambda: appi.create_application(
            Name=name,
            Namespace=namespace,
            Description="duplicate-attempt",
            ApplicationSourceConfig={
                "ExternalUrlConfig": {"AccessUrl": "https://example.com/duplicate"}
            },
        )
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    expected_message = "Application name is invalid. Name already in use."
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # Effect absent: the original application is unmodified by the failed duplicate attempt.
    got = appi.get_application(Arn=arn)
    assert got["Description"] == "original", f"expected 'original', got {got['Description']!r}"
    got_url = got["ApplicationSourceConfig"]["ExternalUrlConfig"]["AccessUrl"]
    assert got_url == "https://example.com/original", f"expected original AccessUrl, got {got_url!r}"

    # Restore: once the conflicting original is deleted, the identical Name+Namespace succeeds.
    appi.delete_application(Arn=arn)
    deleted_code, deleted_message = _client_error(lambda: appi.get_application(Arn=arn))
    assert deleted_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {deleted_code}"
    )
    expected_deleted = f"Could not find Application with identifier: {arn}."
    assert deleted_message == expected_deleted, f"expected {expected_deleted!r}, got {deleted_message!r}"
    restored = appi.create_application(
        Name=name,
        Namespace=namespace,
        Description="restored",
        ApplicationSourceConfig={
            "ExternalUrlConfig": {"AccessUrl": "https://example.com/restored"}
        },
    )
    live_arn["value"] = restored["Arn"]
    got_restored = appi.get_application(Arn=restored["Arn"])
    assert got_restored["Description"] == "restored", (
        f"expected 'restored', got {got_restored['Description']!r}"
    )


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
