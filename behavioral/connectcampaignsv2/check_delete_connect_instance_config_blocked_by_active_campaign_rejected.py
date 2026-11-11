"""delete-connect-instance-config-blocked-by-active-campaign-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-connect-instance-config-blocked-by-active-campaign-rejected"
GROUP = "overly-permissive"
SERVICES = ["connectcampaignsv2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteConnectInstanceConfig fails with InvalidStateException while the instance owns a
    campaign (no campaignDeletionPolicy) and leaves the config in place; after the campaign is
    deleted the same call succeeds, so the rejection tracks the dependency."""
    campaigns = ctx.client("connectcampaignsv2")
    instance_id = _provision_onboarded_instance(ctx)
    flow_id = _create_disconnect_contact_flow(ctx, instance_id)
    phone_number = _claim_phone_number(ctx, instance_id)
    campaign_id = campaigns.create_campaign(
        name=ctx.unique_name("sim2real-campaign-"),
        connectInstanceId=instance_id,
        channelSubtypeConfig={
            "telephony": {
                "capacity": 1.0,
                "outboundMode": {"agentless": {}},
                "defaultOutboundConfig": {
                    "connectContactFlowId": flow_id,
                    "connectSourcePhoneNumber": phone_number,
                },
            }
        },
    )["id"]

    err = _error(lambda: campaigns.delete_connect_instance_config(connectInstanceId=instance_id))
    assert err["Code"] == "InvalidStateException", f"expected InvalidStateException, got {err['Code']}"
    expected_message = "This instance still has campaigns"
    assert err["Message"] == expected_message, (
        f"expected message {expected_message!r}, got {err['Message']!r}"
    )

    # effect absent: config still there
    config = campaigns.get_connect_instance_config(connectInstanceId=instance_id)
    assert config["connectInstanceConfig"]["connectInstanceId"] == instance_id

    # remove the dependency, then the exact same call is a positive control
    campaigns.delete_campaign(id=campaign_id)
    campaigns.delete_connect_instance_config(connectInstanceId=instance_id)

    err_after = _error(lambda: campaigns.get_connect_instance_config(connectInstanceId=instance_id))
    assert err_after["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err_after['Code']}"
    expected_message = f"ConnectInstanceConfig not found {instance_id}."
    assert err_after["Message"] == expected_message, (
        f"expected message {expected_message!r}, got {err_after['Message']!r}"
    )


# ===== helpers =====
def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises, so a target that
    accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_connect_instance(ctx) -> str:
    connect = ctx.client("connect")
    alias = ctx.unique_name("sim2realcc").replace("_", "-")[:60]
    instance_id = connect.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=alias,
        InboundCallsEnabled=True,
        OutboundCallsEnabled=True,
    )["Id"]
    ctx.on_cleanup(lambda: _offboard_and_delete_instance(ctx, instance_id))
    deadline = time.monotonic() + 600
    status = "CREATION_IN_PROGRESS"
    while time.monotonic() < deadline:
        status = connect.describe_instance(InstanceId=instance_id)["Instance"]["InstanceStatus"]
        if status == "ACTIVE":
            return instance_id
        if status == "CREATION_FAILED":
            raise AssertionError("connect instance creation failed")
        time.sleep(3)
    raise AssertionError(f"connect instance never became ACTIVE (last status={status})")


def _provision_onboarded_instance(ctx) -> str:
    campaigns = ctx.client("connectcampaignsv2")
    instance_id = _create_connect_instance(ctx)
    campaigns.start_instance_onboarding_job(
        connectInstanceId=instance_id, encryptionConfig={"enabled": False}
    )
    deadline = time.monotonic() + 120
    status = "IN_PROGRESS"
    while time.monotonic() < deadline:
        status = campaigns.get_instance_onboarding_job_status(connectInstanceId=instance_id)[
            "connectInstanceOnboardingJobStatus"
        ]["status"]
        if status != "IN_PROGRESS":
            break
        time.sleep(3)
    if status != "SUCCEEDED":
        failure_code = _onboarding_failure_code(campaigns, instance_id)
        raise AssertionError(f"instance onboarding did not succeed (status={status}, failureCode={failure_code})")
    return instance_id


def _create_disconnect_contact_flow(ctx, instance_id: str) -> str:
    connect = ctx.client("connect")
    flow_content = json.dumps(
        {
            "Version": "2019-10-30",
            "StartAction": "12345678-1234-1234-1234-123456789012",
            "Actions": [
                {
                    "Identifier": "12345678-1234-1234-1234-123456789012",
                    "Type": "DisconnectParticipant",
                    "Transitions": {},
                    "Parameters": {},
                }
            ],
        }
    )
    resp = connect.create_contact_flow(
        InstanceId=instance_id,
        Name=ctx.unique_name("sim2real-flow-"),
        Type="CONTACT_FLOW",
        Content=flow_content,
    )
    return resp["ContactFlowId"]


def _release_phone_number(connect, phone_number_id):
    # A claimed number can already be gone by teardown time; only a still-present one is released.
    try:
        connect.release_phone_number(PhoneNumberId=phone_number_id)
    except connect.exceptions.ResourceNotFoundException:
        pass


def _claim_phone_number(ctx, instance_id: str) -> str:
    connect = ctx.client("connect")
    target_arn = connect.describe_instance(InstanceId=instance_id)["Instance"]["Arn"]
    numbers = connect.search_available_phone_numbers(
        TargetArn=target_arn,
        PhoneNumberCountryCode="US",
        PhoneNumberType="DID",
        MaxResults=1,
    )["AvailableNumbersList"]
    assert numbers, "no available phone numbers to claim for the test Connect instance"
    phone_number = numbers[0]["PhoneNumber"]
    claim_id = connect.claim_phone_number(TargetArn=target_arn, PhoneNumber=phone_number)[
        "PhoneNumberId"
    ]
    ctx.on_cleanup(lambda: _release_phone_number(connect, claim_id))
    return phone_number


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
    campaigns = ctx.client("connectcampaignsv2")
    deadline = time.monotonic() + _TEARDOWN_TIMEOUT_S

    def _delete_instance():
        try:
            connect.delete_instance(InstanceId=instance_id)
        except connect.exceptions.ResourceNotFoundException:
            return
        while time.monotonic() < deadline:
            try:
                connect.describe_instance(InstanceId=instance_id)
            except connect.exceptions.ResourceNotFoundException:
                return
            time.sleep(2)
        raise AssertionError(f"connect instance {instance_id} still present after {_TEARDOWN_TIMEOUT_S}s")

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
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        _delete_instance_config(campaigns, instance_id, deadline)
    finally:
        # A return here would discard an error raised by the offboarding above, so it lives in a
        # nested function.
        _delete_instance()


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
