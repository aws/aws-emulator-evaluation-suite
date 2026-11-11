"""create-application-conflicting-client-token-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-application-conflicting-client-token-rejected"
GROUP = "overly-permissive"
SERVICES = ["emr-serverless"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Reusing a clientToken with different CreateApplication parameters is a conflict."""
    emrs = ctx.client("emr-serverless")
    token = ctx.unique_name("tok-")
    name_a = ctx.unique_name("sim2real-emrs-app-a-")
    name_b = ctx.unique_name("sim2real-emrs-app-b-")

    first = emrs.create_application(
        name=name_a, releaseLabel="emr-7.0.0", type="SPARK", clientToken=token,
        tags={"env": "test"},
    )
    app_id = first["applicationId"]
    ctx.on_cleanup(lambda: emrs.delete_application(applicationId=app_id))
    _wait_for_application_state(ctx, app_id, {"CREATED"}, timeout_s=180.0)

    code, message = _error(
        lambda: emrs.create_application(
            name=name_b, releaseLabel="emr-7.0.0", type="SPARK", clientToken=token
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    assert message == "Request did not match the original", (
        f"unexpected ConflictException message: {message!r}"
    )

    # effect absent: no second application with name_b was created; the original is untouched
    app = emrs.get_application(applicationId=app_id)["application"]
    assert app["name"] == name_a, f"expected original name {name_a!r} untouched, got {app['name']!r}"

    names = {a["name"] for a in emrs.list_applications(states=["CREATED"]).get("applications", [])}
    assert name_b not in names, f"expected {name_b!r} absent from CREATED applications, found it"

    # positive control: a genuinely new clientToken still creates a new application
    third = emrs.create_application(
        name=name_b, releaseLabel="emr-7.0.0", type="SPARK", clientToken=ctx.unique_name("tok-"),
        tags={"env": "test"},
    )
    other_id = third["applicationId"]
    ctx.on_cleanup(lambda: emrs.delete_application(applicationId=other_id))
    _wait_for_application_state(ctx, other_id, {"CREATED"}, timeout_s=180.0)
    assert other_id != app_id, f"expected a distinct applicationId, got the same id {app_id!r}"


def _wait_for_application_state(ctx, app_id, target_states, timeout_s=180.0, interval_s=5.0):
    emrs = ctx.client("emr-serverless")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = emrs.get_application(applicationId=app_id)["application"]["state"]
        if last in target_states:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"application never reached {target_states}, last state={last}")


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
