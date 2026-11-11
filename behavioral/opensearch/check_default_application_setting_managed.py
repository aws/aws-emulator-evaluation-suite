"""default-application-setting-managed."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "default-application-setting-managed"
GROUP = 'application'
SERVICES = ['opensearch']


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=6.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _error(fn) -> tuple[str, str]:
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected success
    raises, because accepting input AWS refuses is the divergence this check catches."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:opensearch-default-application-setting")
def run(ctx) -> None:
    """PutDefaultApplicationSetting sets the account default and Get reflects it; a nonexistent
    applicationArn is refused with ResourceNotFoundException and leaves the default unchanged."""
    osc = ctx.client("opensearch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    try:
        before = osc.get_default_application_setting()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise
        before = None

    # The default is shared account state, not a deletable resource, so restore it on teardown.
    if before and before.get("applicationArn"):
        _prev_arn = before["applicationArn"]
        ctx.on_cleanup(
            lambda: osc.put_default_application_setting(applicationArn=_prev_arn, setAsDefault=True)
        )

    name = ctx.unique_name("sim2real-behav-app-")[:30].rstrip("-")
    app = osc.create_application(name=name)
    app_id = app["id"]
    ctx.on_cleanup(lambda: osc.delete_application(id=app_id))
    arn = app["arn"]
    _poll_until(
        lambda: osc.get_application(id=app_id),
        lambda a: a.get("status") in ("ACTIVE", "FAILED"),
        timeout_s=180,
        description=f"application {app_id} active",
    )

    put_resp = osc.put_default_application_setting(applicationArn=arn, setAsDefault=True)
    assert put_resp.get("applicationArn") == arn, f"expected {arn}, got {put_resp}"

    got = osc.get_default_application_setting()
    assert got.get("applicationArn") == arn, f"expected default to be {arn}, got {got}"

    # Restore now as well; the registered cleanup covers an assertion raising first.
    if before and before.get("applicationArn") and before["applicationArn"] != arn:
        osc.put_default_application_setting(
            applicationArn=before["applicationArn"], setAsDefault=True
        )
        live_arn = before["applicationArn"]
    else:
        live_arn = arn

    bogus_arn = (
        f"arn:aws:es:{ctx.region}:{account_id}:application/"
        "app-0000000000000000000000000000000000"
    )
    refusal = _error(
        lambda: osc.put_default_application_setting(applicationArn=bogus_arn, setAsDefault=True)
    )
    assert refusal == ("ResourceNotFoundException", f"Application not found for ARN: {bogus_arn}"), (
        f"expected ResourceNotFoundException with AWS's exact message, got {refusal!r}"
    )

    # The rejected Put must not have moved the default; read it back independently.
    after_reject = osc.get_default_application_setting()
    assert after_reject.get("applicationArn") == live_arn, (
        f"a rejected PutDefaultApplicationSetting still changed the default: expected "
        f"{live_arn}, got {after_reject.get('applicationArn')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
