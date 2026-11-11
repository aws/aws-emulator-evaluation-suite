"""concurrent-create-campaign-same-name-one-winner."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-campaign-same-name-one-winner"
GROUP = "concurrency"
SERVICES = ["connectcampaignsv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCampaign enforces per-instance name uniqueness even under concurrent racers: firing
    N CreateCampaign calls with the identical name against the same connectInstanceId at the
    same time results in exactly one success and the rest failing with ConflictException."""
    campaigns = ctx.client("connectcampaignsv2")
    instance_id, instance_arn = _provision_onboarded_instance(ctx)
    flow_id = _create_disconnect_contact_flow(ctx, instance_id)
    source_phone_number = _claim_phone_number(ctx, instance_arn)
    name = ctx.unique_name("sim2real-race-")
    racer_count = 5
    channel_subtype_config = {
        "telephony": {
            "capacity": 1.0,
            "outboundMode": {"agentless": {}},
            "defaultOutboundConfig": {
                "connectContactFlowId": flow_id,
                "connectSourcePhoneNumber": source_phone_number,
            },
        }
    }

    def _create(_i):
        try:
            resp = campaigns.create_campaign(
                name=name,
                connectInstanceId=instance_id,
                channelSubtypeConfig=channel_subtype_config,
                tags={"sim2real": CHECK},
            )
            return ("ok", resp["id"], None)
        except ClientError as err:
            return ("error", err.response["Error"]["Code"], err.response["Error"].get("Message", ""))

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        results = list(pool.map(_create, range(racer_count)))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]

    for _, campaign_id, _message in successes:
        ctx.on_cleanup(lambda cid=campaign_id: campaigns.delete_campaign(id=cid))

    assert len(successes) == 1, f"expected exactly 1 winner, got {len(successes)}: {results}"
    assert len(failures) == racer_count - 1, (
        f"expected {racer_count - 1} losers, got {len(failures)}: {results}"
    )
    assert all(code == "ConflictException" for _, code, _message in failures), (
        f"expected every loser to fail with ConflictException, got: {failures}"
    )
    expected = "Failed due to conflict in current state of the resource."
    for _, _code, message in failures:
        assert message == expected, f"loser ConflictException message {message!r}, expected {expected!r}"

    listing = campaigns.list_campaigns(
        filters={"instanceIdFilter": {"operator": "Eq", "value": instance_id}}
    )
    matching = [c for c in listing["campaignSummaryList"] if c["name"] == name]
    assert len(matching) == 1, (
        f"expected exactly 1 campaign named {name!r} visible at the destination, "
        f"got {len(matching)}: {matching}"
    )


# ===== helpers =====
def _create_connect_instance(ctx) -> tuple[str, str]:
    connect = ctx.client("connect")
    alias = ctx.unique_name("sim2realcc").replace("_", "-")[:60]
    created = connect.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=alias,
        InboundCallsEnabled=True,
        OutboundCallsEnabled=True,
        Tags={"sim2real": CHECK},
    )
    instance_id, instance_arn = created["Id"], created["Arn"]
    ctx.on_cleanup(lambda: _offboard_and_delete_instance(ctx, instance_id))
    deadline = time.monotonic() + 180
    status = "CREATION_IN_PROGRESS"
    while time.monotonic() < deadline:
        status = connect.describe_instance(InstanceId=instance_id)["Instance"]["InstanceStatus"]
        if status == "ACTIVE":
            return instance_id, instance_arn
        if status == "CREATION_FAILED":
            raise AssertionError("connect instance creation failed")
        time.sleep(3)
    raise AssertionError(f"connect instance never became ACTIVE (last status={status})")


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


def _claim_phone_number(ctx, instance_arn: str) -> str:
    connect = ctx.client("connect")
    available = connect.search_available_phone_numbers(
        TargetArn=instance_arn, PhoneNumberCountryCode="US", PhoneNumberType="DID", MaxResults=10
    )["AvailableNumbersList"]
    if not available:
        raise AssertionError("no available DID phone numbers to claim for outbound dialing")
    for candidate in available:
        try:
            claimed = connect.claim_phone_number(
                TargetArn=instance_arn,
                PhoneNumber=candidate["PhoneNumber"],
                Tags={"sim2real": CHECK},
            )
        except connect.exceptions.InvalidParameterException:
            continue
        phone_number_id = claimed["PhoneNumberId"]
        ctx.on_cleanup(lambda pid=phone_number_id: _release_phone_number(connect, pid))
        return candidate["PhoneNumber"]
    raise AssertionError(f"could not claim any of {len(available)} advertised-available DID numbers")


def _release_phone_number(connect, phone_number_id: str) -> None:
    """Release the claimed number; ResourceNotFoundException means it is already released."""
    try:
        connect.release_phone_number(PhoneNumberId=phone_number_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _provision_onboarded_instance(ctx) -> tuple[str, str]:
    campaigns = ctx.client("connectcampaignsv2")
    instance_id, instance_arn = _create_connect_instance(ctx)
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
    return instance_id, instance_arn


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
