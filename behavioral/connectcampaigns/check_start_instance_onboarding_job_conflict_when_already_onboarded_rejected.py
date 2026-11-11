"""start-instance-onboarding-job-conflict-when-already-onboarded-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-instance-onboarding-job-conflict-when-already-onboarded-rejected"
GROUP = "overly-permissive"
SERVICES = ["connectcampaigns"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartInstanceOnboardingJob on an instance that is already successfully onboarded is
    rejected with ConflictException, and the existing onboarding job/config is left untouched
    (still SUCCEEDED), while onboarding a brand-new instance succeeds (positive control)."""
    fixture = _provision_campaign_fixture(ctx)
    campaigns = ctx.client("connectcampaigns")

    status_before = campaigns.get_instance_onboarding_job_status(
        connectInstanceId=fixture["connect_instance_id"]
    )["connectInstanceOnboardingJobStatus"]
    assert status_before["status"] == "SUCCEEDED", (
        f"expected fixture instance already onboarded (SUCCEEDED), got {status_before}"
    )

    code, message = _error(
        lambda: campaigns.start_instance_onboarding_job(
            connectInstanceId=fixture["connect_instance_id"],
            encryptionConfig={"enabled": False},
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code} ({message!r})"
    assert message == (
        f"Instance {fixture['connect_instance_id']} under account {ctx.account} is already onboarded."
    ), message

    status_after = campaigns.get_instance_onboarding_job_status(
        connectInstanceId=fixture["connect_instance_id"]
    )["connectInstanceOnboardingJobStatus"]
    assert status_after["status"] == "SUCCEEDED", "existing onboarding job must be left untouched"

    # Positive control: onboarding a brand-new, never-onboarded instance succeeds.
    control_fixture = _provision_campaign_fixture(ctx)
    control_status = campaigns.get_instance_onboarding_job_status(
        connectInstanceId=control_fixture["connect_instance_id"]
    )["connectInstanceOnboardingJobStatus"]
    assert control_status["status"] == "SUCCEEDED", (
        f"positive control: expected a never-onboarded instance to onboard successfully, got {control_status}"
    )


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed: {last!r}")


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises,
    so an acceptance fails as an acceptance, not as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _provision_campaign_fixture(ctx):
    connect = ctx.client("connect")
    campaigns = ctx.client("connectcampaigns")
    instance_id = connect.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=ctx.unique_name("sim2real-cc-"),
        InboundCallsEnabled=True,
        OutboundCallsEnabled=True,
        Tags={"sim2real": CHECK},
    )["Id"]
    ctx.on_cleanup(lambda: _offboard_and_delete_instance(ctx, instance_id))

    _poll_until(
        lambda: connect.describe_instance(InstanceId=instance_id)["Instance"]["InstanceStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=300.0,
        interval_s=5.0,
    )

    flows = connect.list_contact_flows(
        InstanceId=instance_id, ContactFlowTypes=["CONTACT_FLOW"], MaxResults=25
    )["ContactFlowSummaryList"]
    if not flows:
        raise AssertionError("newly created Connect instance has no default contact flows")
    contact_flow_id = flows[0]["Id"]

    campaigns.start_instance_onboarding_job(
        connectInstanceId=instance_id, encryptionConfig={"enabled": False}
    )

    def _cleanup_onboarding():
        _delete_instance_config(campaigns, instance_id, time.monotonic() + _CONFIG_DELETE_S)
        try:
            campaigns.delete_instance_onboarding_job(connectInstanceId=instance_id)
        except (
            campaigns.exceptions.ResourceNotFoundException,
            campaigns.exceptions.InvalidStateException,
        ):
            pass  # only a FAILED job is deletable; a succeeded one goes with its config

    ctx.on_cleanup(_cleanup_onboarding)

    status = _poll_until(
        lambda: campaigns.get_instance_onboarding_job_status(connectInstanceId=instance_id)[
            "connectInstanceOnboardingJobStatus"
        ],
        lambda s: s["status"] in ("SUCCEEDED", "FAILED"),
        timeout_s=180.0,
        interval_s=3.0,
    )
    if status["status"] != "SUCCEEDED":
        raise AssertionError(f"instance onboarding job failed: {status}")

    return {"connect_instance_id": instance_id, "contact_flow_id": contact_flow_id}


# ===== campaigns teardown =====
# Registered right after the instance exists, so (LIFO) it runs after every campaign cleanup.
# Order: stop/delete leftover campaigns -> delete_connect_instance_config -> delete_instance.
# A campaigns instance config that outlives its instance keeps the instance ARN in an
# account-wide EventBridge rule pattern; past that pattern's 2048-char limit EVERY onboarding in
# the account fails with EVENT_BRIDGE_MANAGED_RULE_LIMIT_EXCEEDED. Config deletion refuses while a
# campaign is active, and both deletes are asynchronous (a pending instance deletion still counts
# against the account's Connect instance quota), so each step is waited out.
_TEARDOWN_TIMEOUT_S = 600
_CONFIG_DELETE_S = 60


def _offboard_and_delete_instance(ctx, instance_id):
    connect = ctx.client("connect")
    campaigns = ctx.client("connectcampaigns")
    deadline = time.monotonic() + _TEARDOWN_TIMEOUT_S
    try:
        leftovers = campaigns.list_campaigns(
            filters={"instanceIdFilter": {"value": instance_id, "operator": "Eq"}}
        )["campaignSummaryList"]
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
