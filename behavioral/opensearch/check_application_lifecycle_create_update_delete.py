"""application-lifecycle-create-update-delete."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "application-lifecycle-create-update-delete"
GROUP = 'application'
SERVICES = ['opensearch']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApplication reaches ACTIVE, UpdateApplication durably changes appConfigs (there is no
    rename), ListApplications shows it, and after DeleteApplication GetApplication is NotFound.
    """
    os = ctx.client("opensearch")
    app_name = ctx.unique_name("sim2real-behav-app-")[:30].rstrip("-")
    create_resp = os.create_application(
        name=app_name,
        tagList=[{"Key": "sim2real", "Value": "application-lifecycle-create-update-delete"}],
    )
    application_id = create_resp["id"]
    def _cleanup():
        try:
            os.delete_application(id=application_id)
        except os.exceptions.ResourceNotFoundException:
            pass  # the check's own delete already removed it

    ctx.on_cleanup(_cleanup)
    assert create_resp["name"] == app_name, (
        f"CreateApplication echoed name {create_resp['name']!r}, expected {app_name!r}"
    )
    assert create_resp.get("arn"), "CreateApplication did not return an ARN"

    # wait until the application reaches a terminal ACTIVE/FAILED status
    _deadline = time.monotonic() + 120
    status = None
    while time.monotonic() < _deadline:
        status = os.get_application(id=application_id).get("status")
        if status in {"ACTIVE", "FAILED"}:
            break
        time.sleep(2)
    else:
        raise AssertionError("application status not met within 120s. Last result: " + repr(status))
    assert status == "ACTIVE", f"expected application to become ACTIVE, got {status}"

    got = os.get_application(id=application_id)
    assert got["name"] == app_name, "GetApplication did not echo the created name"
    assert got["id"] == application_id, f"GetApplication id {got['id']!r} != {application_id!r}"
    assert got.get("arn"), "GetApplication did not return an ARN"

    # UpdateApplication must settle to a terminal status and the new appConfigs value must
    # read back through an independent GetApplication.
    admin_arn = ctx.client("sts").get_caller_identity()["Arn"]
    update_resp = os.update_application(
        id=application_id,
        appConfigs=[{"key": "opensearchDashboards.dashboardAdmin.users", "value": admin_arn}],
    )
    assert update_resp["id"] == application_id, (
        f"UpdateApplication id {update_resp['id']!r} != {application_id!r}"
    )

    _deadline = time.monotonic() + 120
    status = None
    while time.monotonic() < _deadline:
        status = os.get_application(id=application_id).get("status")
        if status in {"ACTIVE", "FAILED"}:
            break
        time.sleep(2)
    else:
        raise AssertionError("application status not met within 120s after update. Last result: " + repr(status))
    assert status == "ACTIVE", f"expected application to return to ACTIVE after update, got {status}"

    updated = os.get_application(id=application_id)
    app_configs = {c["key"]: c.get("value") for c in updated.get("appConfigs", [])}
    assert app_configs.get("opensearchDashboards.dashboardAdmin.users") == admin_arn, (
        f"UpdateApplication's appConfigs value did not persist through GetApplication: {app_configs!r}"
    )

    # ListApplications lists the application (paginated, eventually consistent).
    def _listed():
        ids = []
        for page in os.get_paginator("list_applications").paginate():
            ids += [a["id"] for a in page.get("ApplicationSummaries", [])]
        return ids

    list_deadline = time.monotonic() + max(1.0, min(180.0, (ctx.time_left() or 180.0) - 300.0))
    listed = _listed()
    while application_id not in listed and time.monotonic() < list_deadline:
        time.sleep(2)
        listed = _listed()
    assert application_id in listed, f"ListApplications does not list {application_id!r}: {listed!r}"

    os.delete_application(id=application_id)

    # DeleteApplication is asynchronous: the application stays readable as DELETING until it
    # is removed; the terminal state is ResourceNotFoundException on GetApplication.
    def probe():
        try:
            return os.get_application(id=application_id).get("status")
        except os.exceptions.ResourceNotFoundException:
            return "gone"

    _deadline = time.monotonic() + max(1.0, min(900.0, (ctx.time_left() or 900.0) - 10.0))
    final = probe()
    while final != "gone" and final != "FAILED" and time.monotonic() < _deadline:
        time.sleep(2)
        final = probe()
    assert final == "gone", f"a deleted application must end not found; last status {final!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
