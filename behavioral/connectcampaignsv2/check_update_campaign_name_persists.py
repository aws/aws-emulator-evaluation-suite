"""update-campaign-name-persists."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-campaign-name-persists"
GROUP = "state"
SERVICES = ["connectcampaignsv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateCampaignName renames a campaign; DescribeCampaign and ListCampaigns (scoped to the
    owning instance) both reflect the new name, and the old name is gone from the list."""
    campaigns = ctx.client("connectcampaignsv2")
    instance_id = _provision_onboarded_instance(ctx)
    original_name = ctx.unique_name("sim2real-campaign-")
    # real AWS rejects CreateCampaign with ValidationException "Missing required parameter
    # ChannelConfig" even though channelSubtypeConfig is optional in both the Smithy model and
    # botocore's service-2.json; it also validates connectContactFlowId for existence
    # (ResourceNotFoundException on a placeholder id) and requires a resolvable outbound number
    # (ValidationException "No queue or connectSourcePhoneNumber is supplied" with neither present).
    phone_number = _claim_phone_number(ctx, instance_id)
    channel_config = {
        "telephony": {
            "capacity": 1.0,
            "outboundMode": {"agentless": {}},
            "defaultOutboundConfig": {
                "connectContactFlowId": _default_contact_flow_id(ctx, instance_id),
                "connectSourcePhoneNumber": phone_number,
            },
        }
    }
    campaign_id = campaigns.create_campaign(
        name=original_name,
        connectInstanceId=instance_id,
        channelSubtypeConfig=channel_config,
        tags={"owner": "sim2real", "purpose": "behavioral-check"},
    )["id"]
    ctx.on_cleanup(lambda: campaigns.delete_campaign(id=campaign_id))

    new_name = ctx.unique_name("sim2real-renamed-")
    campaigns.update_campaign_name(id=campaign_id, name=new_name)

    desc = campaigns.describe_campaign(id=campaign_id)["campaign"]
    assert desc["name"] == new_name, f"expected renamed campaign, got name={desc['name']!r}"

    listing = campaigns.list_campaigns(
        filters={"instanceIdFilter": {"operator": "Eq", "value": instance_id}}
    )
    names = {c["id"]: c["name"] for c in listing["campaignSummaryList"]}
    assert names.get(campaign_id) == new_name, (
        f"expected ListCampaigns to show name={new_name!r} for {campaign_id}, got {names.get(campaign_id)!r}"
    )
    assert original_name not in names.values(), (
        f"expected old name {original_name!r} gone from ListCampaigns, still present: {names}"
    )


# ===== helpers =====
def _error_code(fn):
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    return None


def _create_connect_instance(ctx) -> str:
    connect = ctx.client("connect")
    alias = ctx.unique_name("sim2realcc").replace("_", "-")[:60]
    instance_id = connect.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=alias,
        InboundCallsEnabled=True,
        OutboundCallsEnabled=True,
        Tags={"owner": "sim2real", "purpose": "behavioral-check"},
    )["Id"]
    ctx.on_cleanup(lambda: _offboard_and_delete_instance(ctx, instance_id))
    deadline = time.monotonic() + 180
    status = "CREATION_IN_PROGRESS"
    while time.monotonic() < deadline:
        status = connect.describe_instance(InstanceId=instance_id)["Instance"]["InstanceStatus"]
        if status == "ACTIVE":
            return instance_id
        if status == "CREATION_FAILED":
            raise AssertionError("connect instance creation failed")
        time.sleep(3)
    raise AssertionError(f"connect instance never became ACTIVE (last status={status})")


def _default_contact_flow_id(ctx, instance_id: str) -> str:
    connect = ctx.client("connect")
    paginator = connect.get_paginator("list_contact_flows")
    for page in paginator.paginate(InstanceId=instance_id):
        for flow in page["ContactFlowSummaryList"]:
            if flow["ContactFlowType"] == "CONTACT_FLOW":
                return flow["Id"]
    raise AssertionError(f"no CONTACT_FLOW-type flow found on instance {instance_id}")


def _claim_phone_number(ctx, instance_id: str) -> str:
    connect = ctx.client("connect")
    instance_arn = connect.describe_instance(InstanceId=instance_id)["Instance"]["Arn"]
    numbers = connect.search_available_phone_numbers(
        TargetArn=instance_arn,
        PhoneNumberCountryCode="US",
        PhoneNumberType="DID",
        MaxResults=1,
    )["AvailableNumbersList"]
    assert numbers, "no available phone numbers to claim for the test Connect instance"
    phone_number = numbers[0]["PhoneNumber"]
    claim_id = connect.claim_phone_number(TargetArn=instance_arn, PhoneNumber=phone_number)[
        "PhoneNumberId"
    ]
    ctx.on_cleanup(lambda: _release_phone_number(connect, claim_id))
    return phone_number


def _release_phone_number(connect, claim_id: str) -> None:
    """Teardown: release the claimed number; one that already reads not-found is gone."""
    try:
        connect.release_phone_number(PhoneNumberId=claim_id)
    except connect.exceptions.ResourceNotFoundException:
        return


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
