"""create-application-invalid-engine-type-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-application-invalid-engine-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["emr-serverless"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateApplication rejects an engine type that isn't SPARK/HIVE; no application is created.
    The positive control's application is then deleted and proven both gone (absent from
    ListApplications) and unusable (StartApplication on the terminated id is refused)."""
    emrs = ctx.client("emr-serverless")
    bogus_name = ctx.unique_name("sim2real-emrs-bogus-")

    code, message = _error(
        lambda: emrs.create_application(
            name=bogus_name,
            releaseLabel="emr-7.0.0",
            type="NOT_A_REAL_ENGINE",
            clientToken=ctx.unique_name("tok-"),
        )
    )
    assert code == "ValidationException", (
        f"CreateApplication with type='NOT_A_REAL_ENGINE' returned {code!r}, expected "
        f"'ValidationException'"
    )
    assert message == "Type NOT_A_REAL_ENGINE is not supported for release label", (
        f"unexpected CreateApplication invalid-type message: {message!r}"
    )

    # effect absent: no application with that name exists anywhere
    names = {a["name"] for a in _list_all(emrs)}
    assert bogus_name not in names, (
        f"the rejected CreateApplication still produced an application named {bogus_name!r}"
    )

    # positive control: the same call shape with a valid engine type creates successfully
    ok_id = emrs.create_application(
        name=ctx.unique_name("sim2real-emrs-ok-"),
        releaseLabel="emr-7.0.0",
        type="SPARK",
        clientToken=ctx.unique_name("tok-"),
    )["applicationId"]
    ctx.on_cleanup(lambda: _delete_if_present(emrs, ok_id))
    state = _wait_for_application_state(ctx, ok_id, {"CREATED"}, timeout_s=180.0)
    assert state == "CREATED", (
        f"the positive-control application {ok_id!r} reached state {state!r}, expected 'CREATED'"
    )

    # the check already deletes this application in cleanup; make that delete a free negative
    # assertion instead of an unasserted teardown: prove it both gone and unusable.
    # DeleteApplication does not remove the resource -- it transitions it to TERMINATED -- so "gone"
    # is measured via ListApplications.
    emrs.delete_application(applicationId=ok_id)
    terminated_state = _wait_for_application_state(ctx, ok_id, {"TERMINATED"}, timeout_s=180.0)
    assert terminated_state == "TERMINATED", (
        f"deleted application {ok_id!r} reached state {terminated_state!r}, expected 'TERMINATED'"
    )
    live_ids = {a["id"] for a in _list_all(emrs)}
    assert ok_id not in live_ids, (
        f"deleted application {ok_id!r} is still present in ListApplications: {live_ids!r}"
    )
    # message varies: AWS lists the allowed statuses in an unstable order ("[CREATED, STOPPED]" or
    # "[STOPPED, CREATED]") across calls, so only the code is graded here.
    dead_mutation_code, _ = _error(lambda: emrs.start_application(applicationId=ok_id))
    assert dead_mutation_code == "ValidationException", (
        f"StartApplication on terminated application {ok_id!r} returned "
        f"{dead_mutation_code!r}, expected 'ValidationException'"
    )


def _list_all(emrs, **kwargs):
    out = []
    token = None
    while True:
        params = dict(kwargs)
        if token:
            params["nextToken"] = token
        resp = emrs.list_applications(**params)
        out.extend(resp.get("applications", []))
        token = resp.get("nextToken")
        if not token:
            return out


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


def _delete_if_present(emrs, app_id):
    from botocore.exceptions import ClientError
    try:
        emrs.delete_application(applicationId=app_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
