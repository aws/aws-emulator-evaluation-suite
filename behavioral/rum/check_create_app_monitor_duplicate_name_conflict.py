"""create-app-monitor-duplicate-name-conflict."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-app-monitor-duplicate-name-conflict"
GROUP = "error-semantics"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAppMonitor with a Name that already exists in the account/region is
    rejected with ConflictException instead of creating a duplicate resource or
    silently overwriting the existing one."""
    rum = ctx.client("rum")
    app = _create_app_monitor(ctx)

    # Break exactly one thing: create again with the same Name.
    code, message = _client_error(lambda: rum.create_app_monitor(Name=app["name"], Domain="example.net"))
    assert code == "ConflictException", f"expected ConflictException for duplicate Name, got {code!r}"
    expected_message = f"Resource {app['name']} already exists"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the original app monitor is untouched (same Id, original Domain).
    unchanged = rum.get_app_monitor(Name=app["name"])["AppMonitor"]
    assert unchanged["Id"] == app["id"], (
        f"duplicate create must not replace the Id: expected {app['id']!r}, got {unchanged['Id']!r}"
    )
    assert unchanged["Domain"] == "example.com", (
        f"duplicate create must not overwrite Domain: expected 'example.com', got {unchanged['Domain']!r}"
    )

    # Positive control (same file): creating under a fresh, unused name succeeds.
    other = _create_app_monitor(ctx)
    assert other["id"] != app["id"], (
        f"positive control must create a distinct app monitor, got the same Id {other['id']!r}"
    )


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _app_monitor_arn(ctx, name):
    return f"arn:aws:rum:{ctx.region}:{_account_id(ctx)}:appmonitor/{name}"


def _create_app_monitor(ctx, name=None, **kwargs):
    rum = ctx.client("rum")
    name = name or ctx.unique_name("sim2real-rum-am-")
    kwargs.setdefault("Domain", "example.com")
    resp = rum.create_app_monitor(Name=name, **kwargs)

    def _cleanup():
        try:
            rum.delete_app_monitor(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return {"name": name, "id": resp["Id"], "arn": _app_monitor_arn(ctx, name)}


def _client_error(fn):
    """Call fn and return the (code, message) of the ClientError it raises; a success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
