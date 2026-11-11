"""update-application-while-started-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-application-while-started-rejected"
GROUP = "overly-permissive"
SERVICES = ["emr-serverless"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateApplication on a STARTED application accepts maximumCapacity changes (an
    explicitly documented running-application update), but rejects a releaseLabel change,
    which requires the application to be CREATED or STOPPED first."""
    emrs = ctx.client("emr-serverless")
    name = ctx.unique_name("sim2real-emrs-app-")
    app_id = emrs.create_application(
        name=name,
        releaseLabel="emr-7.0.0",
        type="SPARK",
        clientToken=ctx.unique_name("tok-"),
        maximumCapacity={"cpu": "4vCPU", "memory": "8GB"},
        tags={"sim2real-check": CHECK},
    )["applicationId"]
    ctx.on_cleanup(lambda: _cleanup_application(ctx, app_id))
    _wait_for_application_state(ctx, app_id, {"CREATED"}, timeout_s=180.0)

    emrs.start_application(applicationId=app_id)
    _wait_for_application_state(ctx, app_id, {"STARTED"}, timeout_s=300.0)

    # positive control: maximumCapacity updates on a STARTED application are explicitly
    # supported ("Updating Running Applications") and succeed without stopping first
    emrs.update_application(
        applicationId=app_id,
        clientToken=ctx.unique_name("tok-"),
        maximumCapacity={"cpu": "8vCPU", "memory": "16GB"},
    )
    updated = _wait_for_capacity(ctx, app_id, 8, timeout_s=120.0)
    assert updated["maximumCapacity"]["cpu"].strip().upper().startswith("8"), (
        f"expected maximumCapacity.cpu to start with '8' after the running-application update, "
        f"got {updated['maximumCapacity']['cpu']!r}"
    )
    assert updated["maximumCapacity"]["memory"].strip().upper().startswith("16"), (
        f"expected maximumCapacity.memory to start with '16' after the running-application "
        f"update, got {updated['maximumCapacity']['memory']!r}"
    )
    assert updated["state"] == "STARTED", (
        f"expected state to remain STARTED across a maximumCapacity update, got {updated['state']!r}"
    )

    # break exactly one thing: changing releaseLabel is NOT one of the running-application
    # exceptions and must be rejected while STARTED
    code, message = _error(
        lambda: emrs.update_application(
            applicationId=app_id,
            clientToken=ctx.unique_name("tok-"),
            releaseLabel="emr-7.1.0",
        )
    )
    assert code == "ValidationException", (
        f"expected UpdateApplication(releaseLabel=...) on a STARTED application to be rejected "
        f"with ValidationException, got {code!r}"
    )
    assert message == (
        "Only the following configurations can be updated when an application is in STARTED state: "
        "schedulerConfiguration.maxConcurrentRuns, extendedSupportConfiguration, imageConfiguration, "
        "workerTypeSpecifications.imageConfiguration, maximumCapacity."
    ), f"unexpected UpdateApplication message for a STARTED application: {message!r}"

    # effect absent: releaseLabel unchanged while STARTED
    app = emrs.get_application(applicationId=app_id)["application"]
    assert app["releaseLabel"] == "emr-7.0.0", (
        f"expected releaseLabel to remain 'emr-7.0.0' after the rejected update, "
        f"got {app['releaseLabel']!r}"
    )

    # positive control: stop it, then the releaseLabel update succeeds
    emrs.stop_application(applicationId=app_id)
    _wait_for_application_state(ctx, app_id, {"STOPPED"}, timeout_s=300.0)
    emrs.update_application(
        applicationId=app_id,
        clientToken=ctx.unique_name("tok-"),
        releaseLabel="emr-7.1.0",
    )
    final = emrs.get_application(applicationId=app_id)["application"]
    assert final["releaseLabel"] == "emr-7.1.0", (
        f"expected releaseLabel to become 'emr-7.1.0' once the application was STOPPED, "
        f"got {final['releaseLabel']!r}"
    )


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


def _wait_for_capacity(ctx, app_id, expected_cpu_num, timeout_s=120.0, interval_s=5.0):
    import re
    emrs = ctx.client("emr-serverless")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = emrs.get_application(applicationId=app_id)["application"]
        cpu_val = last.get("maximumCapacity", {}).get("cpu", "")
        match = re.match(r"\s*([0-9]+)", cpu_val)
        if match and int(match.group(1)) == expected_cpu_num:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"maximumCapacity never reflected {expected_cpu_num}vCPU, last={last}")


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _cleanup_application(ctx, app_id):
    """delete_application is itself rejected while the application is STARTED, so a body failure
    that leaves the application STARTED must be stopped first or the delete this check registers on
    creation would silently no-op."""
    from botocore.exceptions import ClientError
    emrs = ctx.client("emr-serverless")
    try:
        state = emrs.get_application(applicationId=app_id)["application"]["state"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    if state in ("STARTED", "STARTING"):
        try:
            emrs.stop_application(applicationId=app_id)
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        deadline = time.monotonic() + 40.0
        while time.monotonic() < deadline:
            try:
                state = emrs.get_application(applicationId=app_id)["application"]["state"]
            except ClientError as err:
                if err.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
                return
            if state == "STOPPED":
                break
            time.sleep(5.0)
    try:
        emrs.delete_application(applicationId=app_id)
    except ClientError as exc:
        teardown_code = exc.response.get("Error", {}).get("Code", "")
        if teardown_code not in ("ResourceNotFoundException",):
            raise RuntimeError(
                f"emr-serverless application {app_id!r} not deleted: {exc.response['Error']['Code']}"
            ) from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

