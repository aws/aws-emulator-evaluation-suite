"""default-application-setting-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "default-application-setting-lifecycle"
GROUP = "state-machine"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:opensearch-default-application-setting")
def run(ctx) -> None:
    """PutDefaultApplicationSetting persists a setting retrievable via
    GetDefaultApplicationSetting, and GetDefaultApplicationSetting errors correctly
    once the default is cleared."""
    aos = ctx.client("opensearch")
    app_name = ctx.unique_name("sim2real-osapp-")

    try:
        create_resp = aos.create_application(
            name=app_name, tagList=[{"Key": "sim2real", "Value": CHECK}]
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "DisabledOperationException":
            raise AssertionError("OpenSearch Applications feature not enabled in this account/region")
        raise
    app_id = create_resp["id"]
    app_arn = create_resp["arn"]
    ctx.on_cleanup(lambda: _safe_delete_application(ctx, app_id))

    _wait_application_status(ctx, app_id, {"ACTIVE"}, timeout_s=180.0)

    # Remember any pre-existing default so we can restore it as best-effort cleanup.
    try:
        prior_default = aos.get_default_application_setting().get("applicationArn")
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        prior_default = None

    def _restore_prior_default():
        try:
            if prior_default:
                aos.put_default_application_setting(applicationArn=prior_default, setAsDefault=True)
            else:
                aos.put_default_application_setting(applicationArn=app_arn, setAsDefault=False)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_restore_prior_default)

    put_resp = aos.put_default_application_setting(applicationArn=app_arn, setAsDefault=True)
    assert put_resp["applicationArn"] == app_arn, f"expected {app_arn}, got {put_resp}"

    get_resp = aos.get_default_application_setting()
    assert get_resp["applicationArn"] == app_arn, "default application setting did not persist"

    aos.put_default_application_setting(applicationArn=app_arn, setAsDefault=False)

    refusal = _error(lambda: aos.get_default_application_setting())
    assert refusal == ("ResourceNotFoundException", "No default application is set for this account."), (
        f"expected ResourceNotFoundException with AWS's exact message once no default is "
        f"configured, got {refusal!r}"
    )

    # Restore leg: clearing the default must be reversible, not a one-way trapdoor.
    restore_resp = aos.put_default_application_setting(applicationArn=app_arn, setAsDefault=True)
    assert restore_resp["applicationArn"] == app_arn, f"expected {app_arn}, got {restore_resp}"

    reconfirm = aos.get_default_application_setting()
    assert reconfirm["applicationArn"] == app_arn, (
        f"re-enabling the default after it was cleared did not take effect, got {reconfirm}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, so an emulator accepting what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _wait_application_status(ctx, app_id, ok_statuses, timeout_s=180.0):
    aos = ctx.client("opensearch")

    def probe():
        return aos.get_application(id=app_id)

    result = _poll_until(
        probe,
        lambda a: a.get("status") in ok_statuses or a.get("status") == "FAILED",
        timeout_s=timeout_s,
        interval_s=5.0,
    )
    assert result["status"] in ok_statuses, f"application reached unexpected status: {result}"
    return result


def _safe_delete_application(ctx, app_id):
    aos = ctx.client("opensearch")
    try:
        aos.delete_application(id=app_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
