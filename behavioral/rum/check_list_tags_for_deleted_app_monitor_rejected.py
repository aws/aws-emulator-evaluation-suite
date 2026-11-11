"""list-tags-for-deleted-app-monitor-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-for-deleted-app-monitor-rejected"
GROUP = "error-semantics"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource on a deleted app monitor's ARN answers NotFoundException once the
    deletion has finished, with the message "Resource was not found".
    """
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-rum-am-")
    rum.create_app_monitor(Name=name, Domain="example.com", Tags={"Team": "rum-fidelity"})
    arn = _app_monitor_arn(ctx, name)

    def _cleanup():
        try:
            rum.delete_app_monitor(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    # Positive control (same file, before deletion): tags are visible while the app
    # monitor exists.
    before = rum.list_tags_for_resource(ResourceArn=arn)
    assert before["Tags"]["Team"] == "rum-fidelity", f"expected tag Team=rum-fidelity, got {before['Tags']!r}"

    rum.delete_app_monitor(Name=name)

    # DeleteAppMonitor moves the resource through a DELETING transition before it is
    # fully removed; poll for the resource to be actually gone rather than asserting
    # immediately at the boundary.
    gone_code, _ = _poll_for_error(lambda: rum.get_app_monitor(Name=name), timeout_s=60.0, interval_s=2.0)
    assert gone_code == "ResourceNotFoundException", f"app monitor {name} not deleted, got {gone_code!r}"

    code, message = _client_error(lambda: rum.list_tags_for_resource(ResourceArn=arn))
    assert code == "NotFoundException", f"got {code!r}"
    assert message == "Resource was not found", message


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _app_monitor_arn(ctx, name):
    return f"arn:aws:rum:{ctx.region}:{_account_id(ctx)}:appmonitor/{name}"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _poll_for_error(fn, *, timeout_s: float, interval_s: float):
    """Poll until fn() is refused; return the (code, message). A success keeps polling until the
    deadline, then raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return _client_error(fn)
        except AssertionError as exc:
            if time.monotonic() >= deadline:
                raise AssertionError(f"call was not refused within {timeout_s}s: {exc}") from None
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
