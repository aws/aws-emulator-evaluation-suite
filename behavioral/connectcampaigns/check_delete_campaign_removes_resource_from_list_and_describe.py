"""delete-campaign-removes-resource-from-list-and-describe."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-campaign-removes-resource-from-list-and-describe"
GROUP = "lifecycle"
SERVICES = ["connectcampaigns"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deleting one of two sibling campaigns makes it permanently un-describable
    (ResourceNotFoundException) while the surviving sibling campaign remains fully
    describable."""
    instance_id, flow_id = _create_onboarded_instance(ctx)
    keep_id, _keep_arn = _create_campaign(
        ctx, instance_id, flow_id, name=ctx.unique_name("sim2real-keep-")
    )
    delete_id, _delete_arn = _create_campaign(
        ctx, instance_id, flow_id, name=ctx.unique_name("sim2real-delete-")
    )
    cc = ctx.client("connectcampaigns")

    cc.delete_campaign(id=delete_id)

    deadline = time.monotonic() + 60
    code = message = None
    while time.monotonic() < deadline:
        code, message = _error_code_and_message(lambda: cc.describe_campaign(id=delete_id))
        if code == "ResourceNotFoundException":
            break
        time.sleep(2)
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == f"CampaignId not found {delete_id}.", message

    # a mutation on the dead id also fails, not just the read
    pause_code, pause_message = _error_code_and_message(lambda: cc.pause_campaign(id=delete_id))
    assert pause_code == "ResourceNotFoundException", (
        f"PauseCampaign on a deleted campaign should fail not-found, got {pause_code}"
    )
    assert pause_message == f"Campaign: {delete_id} doesn't exist", pause_message

    # independent read via ListCampaigns: the deleted campaign is gone from the
    # instance's campaign list, the surviving sibling is still in it
    listed_ids = {
        c["id"]
        for c in cc.list_campaigns(
            filters={"instanceIdFilter": {"value": instance_id, "operator": "Eq"}}
        )["campaignSummaryList"]
    }
    assert delete_id not in listed_ids, f"deleted campaign {delete_id} still in ListCampaigns"
    assert keep_id in listed_ids, f"surviving campaign {keep_id} missing from ListCampaigns"

    # positive control: the sibling campaign is unaffected
    kept = cc.describe_campaign(id=keep_id)["campaign"]
    assert kept["id"] == keep_id, f"expected sibling campaign {keep_id}, got {kept['id']}"


# ===== helpers =====
_FLOW_CONTENT = json.dumps(
    {
        "Version": "2019-10-30",
        "StartAction": "12345678-1234-1234-1234-123456789012",
        "Actions": [
            {
                "Identifier": "12345678-1234-1234-1234-123456789012",
                "Type": "DisconnectParticipant",
                "Parameters": {},
                "Transitions": {},
            }
        ],
    }
)


_CALL_SUCCEEDED = "<call succeeded>"


def _error_code_and_message(fn):
    """The botocore error code and message fn() raised, or a sentinel no error code can equal
    when the call succeeds (so a poll can wait on it and an assert on a code fails loudly)."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    return _CALL_SUCCEEDED, repr(result)[:300]


def _create_onboarded_instance(ctx):
    connect = ctx.client("connect")
    cc = ctx.client("connectcampaigns")

    instance_id = connect.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=ctx.unique_name("sim2real-cc-"),
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

    flow_id = connect.create_contact_flow(
        InstanceId=instance_id,
        Name=ctx.unique_name("sim2real-cc-flow-"),
        Type="CONTACT_FLOW",
        Content=_FLOW_CONTENT,
    )["ContactFlowId"]

    cc.start_instance_onboarding_job(
        connectInstanceId=instance_id, encryptionConfig={"enabled": False}
    )
    ctx.on_cleanup(lambda: _safe_delete_instance_config(ctx, instance_id))

    deadline = time.monotonic() + 180
    status = None
    while time.monotonic() < deadline:
        status = cc.get_instance_onboarding_job_status(connectInstanceId=instance_id)[
            "connectInstanceOnboardingJobStatus"
        ]["status"]
        if status == "SUCCEEDED":
            break
        if status == "FAILED":
            failure_code = _onboarding_failure_code(cc, instance_id)
            raise AssertionError(f"instance onboarding job failed (failureCode={failure_code})")
        time.sleep(3)
    else:
        raise AssertionError(f"onboarding job never reached SUCCEEDED (last status={status})")

    return instance_id, flow_id


def _safe_delete_instance_config(ctx, instance_id):
    cc = ctx.client("connectcampaigns")
    _teardown(
        lambda: cc.delete_connect_instance_config(connectInstanceId=instance_id),
        busy=_CAMPAIGNS_LEFT,
    )


def _create_campaign(ctx, instance_id, flow_id, dialer_config=None, name=None):
    cc = ctx.client("connectcampaigns")
    connect = ctx.client("connect")
    instance_arn = connect.describe_instance(InstanceId=instance_id)["Instance"]["Arn"]
    numbers = connect.search_available_phone_numbers(
        TargetArn=instance_arn,
        PhoneNumberCountryCode="US",
        PhoneNumberType="DID",
        MaxResults=10,
    )["AvailableNumbersList"]
    assert numbers, "no available phone numbers to claim for the test Connect instance"
    # the search pool is shared account-wide, so a candidate another concurrent
    # claim just took is expected — retry the next candidate, not a sleep
    phone_number = None
    claim_id = None
    for candidate in numbers:
        try:
            claim_id = connect.claim_phone_number(
                TargetArn=instance_arn, PhoneNumber=candidate["PhoneNumber"]
            )["PhoneNumberId"]
            phone_number = candidate["PhoneNumber"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException":
                raise
    assert claim_id is not None, f"could not claim any of {len(numbers)} candidate numbers"
    ctx.on_cleanup(lambda: _release_phone_number(connect, claim_id))

    resp = cc.create_campaign(
        name=name or ctx.unique_name("sim2real-campaign-"),
        connectInstanceId=instance_id,
        dialerConfig=dialer_config or {"agentlessDialerConfig": {"dialingCapacity": 1.0}},
        outboundCallConfig={
            "connectContactFlowId": flow_id,
            "connectSourcePhoneNumber": phone_number,
        },
        tags={"sim2real": CHECK},
    )
    campaign_id = resp["id"]
    ctx.on_cleanup(lambda: _safe_delete_campaign(ctx, campaign_id))
    return campaign_id, resp["arn"]


def _safe_delete_campaign(ctx, campaign_id):
    cc = ctx.client("connectcampaigns")
    _teardown(lambda: cc.delete_campaign(id=campaign_id))


# DeleteConnectInstanceConfig refuses while a just-deleted campaign is still being removed.
_CAMPAIGNS_LEFT = ("InvalidStateException",)


def _teardown(fn, done=(), busy=()):
    """Run one teardown call. ResourceNotFoundException or a code in `done` means nothing is left to
    delete; a code in `busy` (a dependency still being released) is retried every 2 s for up to 60 s;
    anything else raises."""
    deadline = time.monotonic() + 60
    while True:
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException" or code in done:
                return
            if code not in busy or time.monotonic() >= deadline:
                raise
        time.sleep(2)


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
        except campaigns.exceptions.ValidationException as err:
            # An instance whose config is already deleted is not onboarded and has no campaigns.
            if "not onboarded" not in err.response["Error"]["Message"]:
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


def _release_phone_number(connect, claim_id):
    # Teardown only: a number Connect already released reads as not-found.
    try:
        connect.release_phone_number(PhoneNumberId=claim_id)
    except connect.exceptions.ResourceNotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
