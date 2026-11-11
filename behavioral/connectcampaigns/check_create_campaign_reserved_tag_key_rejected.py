"""create-campaign-reserved-tag-key-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-campaign-reserved-tag-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["connectcampaigns"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCampaign rejects an 'aws:'-prefixed tag key with BadRequestException naming the prefix
    and creates no campaign, while the same request with a normal tag key succeeds (control)."""
    fixture = _provision_campaign_fixture(ctx)
    campaigns = ctx.client("connectcampaigns")

    rejected_name = ctx.unique_name("sim2real-campaign-reserved-tag-")
    code, message = _error_code_and_message(
        lambda: campaigns.create_campaign(
            name=rejected_name,
            connectInstanceId=fixture["connect_instance_id"],
            dialerConfig={"agentlessDialerConfig": {"dialingCapacity": 1.0}},
            outboundCallConfig={
                "connectContactFlowId": fixture["contact_flow_id"],
                "connectSourcePhoneNumber": fixture["phone_number"],
            },
            tags={"aws:reserved": "nope"},
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}: {message}"
    assert message == (
        "Invalid tag key. Customers cannot set tag keys starting with aws: (case insensitive)"
    ), f"unexpected message: {message!r}"

    # Effect absent: no campaign with the rejected name exists under this instance.
    names = _all_campaign_names_for_instance(ctx, fixture["connect_instance_id"])
    assert rejected_name not in names, "a campaign must not have been created despite the rejection"

    # Positive control: an otherwise-identical request with a normal tag key succeeds,
    # and the tag is visible through an independent read at the destination.
    normal_tag_key = "sim2real-normal-tag"
    campaign = _create_campaign(ctx, fixture, tags={normal_tag_key: "ok"})
    described = campaigns.describe_campaign(id=campaign["id"])["campaign"]
    assert described["id"] == campaign["id"], f"expected {campaign['id']!r}, got {described['id']!r}"
    persisted_tags = campaigns.list_tags_for_resource(arn=campaign["arn"])["tags"]
    assert persisted_tags.get(normal_tag_key) == "ok", (
        f"expected tag {normal_tag_key!r}='ok' to persist, got {persisted_tags!r}"
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


def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _all_campaign_names_for_instance(ctx, connect_instance_id):
    campaigns = ctx.client("connectcampaigns")
    names = []
    next_token = None
    for _ in range(20):
        kwargs = {"maxResults": 50}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = campaigns.list_campaigns(**kwargs)
        for summary in resp.get("campaignSummaryList", []):
            if summary.get("connectInstanceId") == connect_instance_id:
                names.append(summary["name"])
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return names


def _provision_campaign_fixture(ctx):
    connect = ctx.client("connect")
    campaigns = ctx.client("connectcampaigns")
    instance_id = connect.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=ctx.unique_name("sim2real-cc-"),
        InboundCallsEnabled=True,
        OutboundCallsEnabled=True,
    )["Id"]
    ctx.on_cleanup(lambda: _offboard_and_delete_instance(ctx, instance_id))

    _poll_until(
        lambda: connect.describe_instance(InstanceId=instance_id)["Instance"]["InstanceStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=600.0,
        interval_s=5.0,
    )

    flows = connect.list_contact_flows(
        InstanceId=instance_id, ContactFlowTypes=["CONTACT_FLOW"], MaxResults=25
    )["ContactFlowSummaryList"]
    if not flows:
        raise AssertionError("newly created Connect instance has no default contact flows")
    contact_flow_id = flows[0]["Id"]

    instance_arn = connect.describe_instance(InstanceId=instance_id)["Instance"]["Arn"]
    numbers = connect.search_available_phone_numbers(
        TargetArn=instance_arn, PhoneNumberCountryCode="US", PhoneNumberType="DID", MaxResults=1
    )["AvailableNumbersList"]
    if not numbers:
        raise AssertionError("no available phone numbers to claim for the test Connect instance")
    phone_number = numbers[0]["PhoneNumber"]
    claim_id = connect.claim_phone_number(TargetArn=instance_arn, PhoneNumber=phone_number)[
        "PhoneNumberId"
    ]
    ctx.on_cleanup(lambda: _release_phone_number(connect, claim_id))

    campaigns.start_instance_onboarding_job(
        connectInstanceId=instance_id, encryptionConfig={"enabled": False}
    )

    def _cleanup_onboarding():
        _teardown(
            lambda: campaigns.delete_connect_instance_config(connectInstanceId=instance_id),
            busy=_CAMPAIGNS_LEFT,
        )
        _teardown(
            lambda: campaigns.delete_instance_onboarding_job(connectInstanceId=instance_id),
            done=_JOB_NOT_DELETABLE,
        )

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

    return {
        "connect_instance_id": instance_id,
        "contact_flow_id": contact_flow_id,
        "phone_number": phone_number,
    }


def _create_campaign(ctx, fixture, *, dialer_config=None, name=None, tags=None):
    campaigns = ctx.client("connectcampaigns")
    kwargs = {
        "name": name or ctx.unique_name("sim2real-campaign-"),
        "connectInstanceId": fixture["connect_instance_id"],
        "dialerConfig": dialer_config or {"agentlessDialerConfig": {"dialingCapacity": 1.0}},
        "outboundCallConfig": {
            "connectContactFlowId": fixture["contact_flow_id"],
            "connectSourcePhoneNumber": fixture["phone_number"],
        },
    }
    if tags:
        kwargs["tags"] = tags
    resp = campaigns.create_campaign(**kwargs)
    campaign_id = resp["id"]
    ctx.on_cleanup(lambda: campaigns.delete_campaign(id=campaign_id))
    return {"id": campaign_id, "arn": resp["arn"]}


# Only a failed onboarding job can be deleted; any other job goes with the instance config.
_JOB_NOT_DELETABLE = ("InvalidStateException",)
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


def _release_phone_number(connect, claim_id):
    # Teardown only: a number Connect already released reads as not-found.
    try:
        connect.release_phone_number(PhoneNumberId=claim_id)
    except connect.exceptions.ResourceNotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
