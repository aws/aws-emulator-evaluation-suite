"""application-tagging-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "application-tagging-lifecycle"
GROUP = "state-machine"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags added to an application persist through ListTags/GetApplication/
    ListApplications, survive an UpdateApplication call, and are fully removed
    after RemoveTags and DeleteApplication."""
    aos = ctx.client("opensearch")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    app_name = ctx.unique_name("sim2real-osapp-")

    try:
        create_resp = aos.create_application(
            name=app_name, tagList=[{"Key": "sim2real", "Value": "initial"}]
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "DisabledOperationException":
            raise AssertionError("OpenSearch Applications feature not enabled in this account/region")
        raise
    app_id = create_resp["id"]
    app_arn = create_resp["arn"]
    ctx.on_cleanup(lambda: _safe_delete_application(ctx, app_id))

    _wait_application_status(ctx, app_id, {"ACTIVE"})

    tags_now = aos.list_tags(ARN=app_arn)["TagList"]
    assert {"Key": "sim2real", "Value": "initial"} in tags_now

    aos.add_tags(ARN=app_arn, TagList=[{"Key": "env", "Value": "sim2real-test"}])
    tags_after_add = {t["Key"]: t["Value"] for t in aos.list_tags(ARN=app_arn)["TagList"]}
    assert tags_after_add.get("env") == "sim2real-test"
    assert tags_after_add.get("sim2real") == "initial"

    got = aos.get_application(id=app_id)
    assert got["name"] == app_name
    assert got["arn"] == app_arn

    # ListApplications is eventually consistent: a just-created (even ACTIVE) application
    # can be absent from this listing for a while, so a single-shot membership check can
    # false-negative a target that is behaving correctly. Poll it instead of asserting once.
    _poll_until(
        lambda: any(a["id"] == app_id for a in _list_all_applications(aos)),
        lambda found: found,
        timeout_s=180.0,
        interval_s=10.0,
    )

    admin_arn = f"arn:aws:iam::{account_id}:user/sim2real-dashboard-admin"
    aos.update_application(
        id=app_id,
        appConfigs=[{"key": "opensearchDashboards.dashboardAdmin.users", "value": admin_arn}],
    )
    updated = _wait_application_status(ctx, app_id, {"ACTIVE"})
    app_configs = {c["key"]: c["value"] for c in updated.get("appConfigs", [])}
    assert app_configs.get("opensearchDashboards.dashboardAdmin.users") == admin_arn

    tags_after_update = {t["Key"]: t["Value"] for t in aos.list_tags(ARN=app_arn)["TagList"]}
    assert tags_after_update.get("env") == "sim2real-test", "tags did not survive UpdateApplication"
    assert tags_after_update.get("sim2real") == "initial"

    aos.remove_tags(ARN=app_arn, TagKeys=["env"])
    tags_after_remove = {t["Key"]: t["Value"] for t in aos.list_tags(ARN=app_arn)["TagList"]}
    assert "env" not in tags_after_remove
    assert tags_after_remove.get("sim2real") == "initial"

    aos.delete_application(id=app_id)

    # DeleteApplication does not remove the application synchronously: GetApplication
    # keeps answering while the delete runs, so poll (bounded) until it reports not-found.
    _poll_until(
        lambda: _status_or_error_code(aos, app_id),
        lambda state: state == "ResourceNotFoundException",
        timeout_s=600.0,
        interval_s=10.0,
    )
    try:
        gone = aos.get_application(id=app_id)
    except ClientError as e:
        message = e.response["Error"].get("Message", "")
    else:
        raise AssertionError(f"GetApplication answered after not-found was observed: {gone!r}")
    expected = "Application does not exist"
    assert message == expected, f"deleted-application message: expected {expected!r}, got {message!r}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _status_or_error_code(aos, app_id):
    """The application's status while GetApplication answers, else the error code it raises."""
    try:
        return aos.get_application(id=app_id)["status"]
    except ClientError as e:
        return e.response["Error"]["Code"]


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


def _list_all_applications(aos):
    out = []
    resp = aos.list_applications()
    out.extend(resp.get("ApplicationSummaries", []))
    while resp.get("nextToken"):
        resp = aos.list_applications(nextToken=resp["nextToken"])
        out.extend(resp.get("ApplicationSummaries", []))
    return out


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
