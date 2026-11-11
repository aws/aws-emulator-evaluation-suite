"""instance-onboarding-job-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "instance-onboarding-job-lifecycle"
GROUP = "onboarding"
SERVICES = ["connectcampaigns"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartInstanceOnboardingJob onboards an instance (a repeat call reports the current job,
    which still SUCCEEDS); DeleteConnectInstanceConfig removes the config, a second
    delete is not-found, and onboarding can be started again."""
    connect = ctx.client("connect")
    cc = ctx.client("connectcampaigns")

    instance_id = connect.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=ctx.unique_name("sim2real-cc-onb-"),
        InboundCallsEnabled=True,
        OutboundCallsEnabled=True,
        Tags={"sim2real": CHECK},
    )["Id"]
    ctx.on_cleanup(lambda: _offboard_and_delete_instance(ctx, instance_id))

    deadline = time.monotonic() + 600
    status = None
    while time.monotonic() < deadline:
        status = connect.describe_instance(InstanceId=instance_id)["Instance"]["InstanceStatus"]
        if status == "ACTIVE":
            break
        if status == "FAILED":
            raise AssertionError("connect instance creation failed")
        time.sleep(5)
    else:
        raise AssertionError(f"connect instance never became ACTIVE (last status={status})")

    # no config exists yet for an un-onboarded instance
    not_found = ("ResourceNotFoundException", f"ConnectInstanceConfig not found {instance_id}.")
    before = _client_error(lambda: cc.get_connect_instance_config(connectInstanceId=instance_id))
    assert before == not_found, before

    cc.start_instance_onboarding_job(
        connectInstanceId=instance_id, encryptionConfig={"enabled": False}
    )

    # a second onboarding request issued immediately is NOT a conflict: AWS answers idempotently
    # with the current job's status rather than starting (or refusing) a second job. That job is
    # IN_PROGRESS, or SUCCEEDED once a fast onboarding has already finished; never FAILED.
    dup_status = cc.start_instance_onboarding_job(
        connectInstanceId=instance_id, encryptionConfig={"enabled": False}
    )["connectInstanceOnboardingJobStatus"]
    assert dup_status.get("connectInstanceId") == instance_id, dup_status
    assert dup_status.get("status") in ("IN_PROGRESS", "SUCCEEDED"), (
        f"expected the duplicate call to report the current job IN_PROGRESS or SUCCEEDED, got "
        f"{dup_status}"
    )

    # positive control: the original job was not disrupted by the duplicate call and still
    # reaches SUCCEEDED
    _wait_onboarding_succeeded(cc, instance_id)

    config = cc.get_connect_instance_config(connectInstanceId=instance_id)["connectInstanceConfig"]
    assert config["connectInstanceId"] == instance_id, (
        f"expected connectInstanceId {instance_id}, got {config.get('connectInstanceId')}"
    )

    cc.delete_connect_instance_config(connectInstanceId=instance_id)
    after = _client_error(lambda: cc.get_connect_instance_config(connectInstanceId=instance_id))
    assert after == not_found, after

    # a second delete on the now-gone config is a not-found, not a silent success
    double_delete = _client_error(
        lambda: cc.delete_connect_instance_config(connectInstanceId=instance_id)
    )
    assert double_delete == ("ResourceNotFoundException", _NOT_ONBOARDED), double_delete

    # the identifier is reusable: with its config gone, the instance can be re-onboarded
    reuse_status = cc.start_instance_onboarding_job(
        connectInstanceId=instance_id, encryptionConfig={"enabled": False}
    )["connectInstanceOnboardingJobStatus"]
    assert reuse_status.get("status") in ("IN_PROGRESS", "SUCCEEDED"), (
        f"expected re-onboarding after delete to start a fresh job, IN_PROGRESS or already "
        f"SUCCEEDED, got {reuse_status}"
    )
    _wait_onboarding_succeeded(cc, instance_id)


#: The refusal for the instance this check created once its onboarding config is deleted: a
#: property of that instance, not of the account.
_NOT_ONBOARDED = "Instance is not onboarded"

# ===== helpers =====
def _wait_onboarding_succeeded(cc, instance_id):
    """Poll the instance's onboarding job to SUCCEEDED; FAILED or the deadline raises."""
    deadline = time.monotonic() + 180
    job_status = None
    while time.monotonic() < deadline:
        job_status = cc.get_instance_onboarding_job_status(connectInstanceId=instance_id)[
            "connectInstanceOnboardingJobStatus"
        ]["status"]
        if job_status == "SUCCEEDED":
            return
        if job_status == "FAILED":
            failure_code = _onboarding_failure_code(cc, instance_id)
            raise AssertionError(f"instance onboarding job failed (failureCode={failure_code})")
        time.sleep(3)
    raise AssertionError(f"onboarding job never reached SUCCEEDED (last status={job_status})")


def _client_error(fn):
    """Call fn(); return its botocore Error code and message. An unexpected SUCCESS raises, so a
    call that should be refused but is accepted fails as such, not as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


# ===== campaigns teardown =====
# Registered right after the instance exists, so (LIFO) it runs after every campaign cleanup.
# Order: stop/delete leftover campaigns -> delete_connect_instance_config -> delete_instance.
# A campaigns instance config that outlives its instance keeps the instance ARN in an
# account-wide EventBridge rule pattern; past that pattern's 2048-char limit EVERY onboarding in
# the account fails with EVENT_BRIDGE_MANAGED_RULE_LIMIT_EXCEEDED. Config deletion refuses while a
# campaign is active, and both deletes are asynchronous (a pending instance deletion still counts
# against the account's Connect instance quota), so each step is waited out.
_TEARDOWN_TIMEOUT_S = 600


def _offboard_and_delete_instance(ctx, instance_id):
    connect = ctx.client("connect")
    campaigns = ctx.client("connectcampaigns")
    deadline = time.monotonic() + _TEARDOWN_TIMEOUT_S
    try:
        try:
            leftovers = campaigns.list_campaigns(
                filters={"instanceIdFilter": {"value": instance_id, "operator": "Eq"}}
            )["campaignSummaryList"]
        except campaigns.exceptions.ValidationException as exc:
            # An instance that is not onboarded holds no campaigns.
            if exc.response["Error"].get("Message") != _NOT_ONBOARDED:
                raise
            leftovers = []
        for summary in leftovers:
            try:
                if campaigns.get_campaign_state(id=summary["id"])["state"] in ("Running", "Paused"):
                    campaigns.stop_campaign(id=summary["id"])
                    while time.monotonic() < deadline and campaigns.get_campaign_state(
                        id=summary["id"]
                    )["state"] in ("Running", "Paused"):
                        time.sleep(2)
                campaigns.delete_campaign(id=summary["id"])
            except campaigns.exceptions.ResourceNotFoundException:
                pass
        _delete_instance_config(campaigns, instance_id, deadline)
    finally:
        try:
            connect.delete_instance(InstanceId=instance_id)
        except connect.exceptions.ResourceNotFoundException:
            pass
        while True:
            try:
                connect.describe_instance(InstanceId=instance_id)
            except connect.exceptions.ResourceNotFoundException:
                break
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"Connect instance {instance_id} still exists {_TEARDOWN_TIMEOUT_S}s after DeleteInstance"
                )
            time.sleep(2)


def _delete_instance_config(campaigns, instance_id, deadline):
    """Teardown: delete the instance config until it reads not-found; the refusal while a
    campaign on the instance is still being released (InvalidStateException) is retried."""
    while True:
        try:
            campaigns.get_connect_instance_config(connectInstanceId=instance_id)
            campaigns.delete_connect_instance_config(connectInstanceId=instance_id)
        except campaigns.exceptions.ResourceNotFoundException:
            return
        except campaigns.exceptions.InvalidStateException:
            if time.monotonic() >= deadline:
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"campaigns config for instance {instance_id} outlived its teardown deadline")
        time.sleep(2)


def _onboarding_failure_code(campaigns, instance_id):
    # The job status carries the cause (e.g. EVENT_BRIDGE_MANAGED_RULE_LIMIT_EXCEEDED); a failure
    # message without it sends the reader hunting.
    try:
        return campaigns.get_instance_onboarding_job_status(connectInstanceId=instance_id)[
            "connectInstanceOnboardingJobStatus"
        ].get("failureCode")
    except Exception as e:
        return f"<unreadable: {type(e).__name__}>"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
