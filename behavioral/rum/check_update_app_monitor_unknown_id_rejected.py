"""update-app-monitor-unknown-id-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-app-monitor-unknown-id-rejected"
GROUP = "error-semantics"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAppMonitor on a name with no app monitor fails with ResourceNotFoundException and the exact
    message 'Resource not found <name>', while the same call on an existing app monitor persists the new
    Domain."""
    rum = ctx.client("rum")
    missing_name = ctx.unique_name("sim2real-rum-missing-")

    err = _client_error(
        lambda: rum.update_app_monitor(Name=missing_name, Domain="example.org")
    )
    assert err["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err!r}"
    expected_message = f"Resource not found {missing_name}"
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # Positive control (same file): the same call against a real app monitor succeeds
    # and the change is actually persisted.
    app = _create_app_monitor(ctx)
    rum.update_app_monitor(Name=app["name"], Domain="example.org")
    updated = rum.get_app_monitor(Name=app["name"])["AppMonitor"]
    assert updated["Domain"] == "example.org", f"expected persisted Domain example.org, got {updated.get('Domain')!r}"


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _app_monitor_arn(ctx, name):
    return f"arn:aws:rum:{ctx.region}:{_account_id(ctx)}:appmonitor/{name}"


def _create_app_monitor(ctx, name=None, **kwargs):
    rum = ctx.client("rum")
    name = name or ctx.unique_name("sim2real-rum-am-")
    kwargs.setdefault("Domain", "example.com")
    kwargs.setdefault("Tags", {"Team": "rum-fidelity"})
    resp = rum.create_app_monitor(Name=name, **kwargs)

    def _cleanup():
        try:
            rum.delete_app_monitor(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return {"name": name, "id": resp["Id"], "arn": _app_monitor_arn(ctx, name)}


def _client_error(fn) -> dict:
    """Call fn(); return the botocore Error dict (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
