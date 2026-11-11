"""create-campaign-name-too-long-rejected."""
from __future__ import annotations
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-campaign-name-too-long-rejected"
GROUP = "overly-permissive"
SERVICES = ["connectcampaigns"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCampaign with a name over 127 characters fails with ValidationException and the exact
    length-constraint message, while a valid name fails differently ("Connect Instance does not exist or
    is not enabled to use Campaigns."), and ListCampaigns shows neither campaign."""
    cc = ctx.client("connectcampaigns")
    too_long_name = "x" * 128
    # UUID-shaped instance id so the control fails on "not onboarded", not on id format.
    fake_instance_id = str(uuid.uuid4())
    dialer_config = {"agentlessDialerConfig": {"dialingCapacity": 1.0}}
    outbound_call_config = {"connectContactFlowId": "some-contact-flow-id"}

    def _create_too_long():
        return cc.create_campaign(
            name=too_long_name,
            connectInstanceId=fake_instance_id,
            dialerConfig=dialer_config,
            outboundCallConfig=outbound_call_config,
        )

    code, message = _error_code_and_message(_create_too_long)
    assert code == "ValidationException", f"{code}: {message}"
    assert message == (
        "1 validation error detected: Value at 'name' failed to satisfy constraint: "
        "Member must have length less than or equal to 127"
    ), message

    # positive control: the same request shape with a valid-length name still fails
    # ValidationException, but for the connectInstanceId (not onboarded), NOT the name --
    # the message no longer references the name/length constraint.
    valid_name = ctx.unique_name("sim2real-campaign-")

    def _create_valid_name():
        return cc.create_campaign(
            name=valid_name,
            connectInstanceId=fake_instance_id,
            dialerConfig=dialer_config,
            outboundCallConfig=outbound_call_config,
        )

    control_code, control_message = _error_code_and_message(_create_valid_name)
    assert control_code == "ValidationException", f"{control_code}: {control_message}"
    assert control_message == "Connect Instance does not exist or is not enabled to use Campaigns.", (
        control_message
    )

    # effect absent: neither rejected call left a campaign behind, proven by an independent
    # read (ListCampaigns) rather than by trusting the mutating calls' own responses.
    listed_names = _all_campaign_names(cc)
    assert too_long_name not in listed_names, (
        f"a campaign named {too_long_name!r} exists despite the rejected CreateCampaign call"
    )
    assert valid_name not in listed_names, (
        f"a campaign named {valid_name!r} exists despite the rejected CreateCampaign call"
    )


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected CreateCampaign to be rejected, but it SUCCEEDED: {result!r}")


def _all_campaign_names(cc):
    names = []
    next_token = None
    for _ in range(20):
        kwargs = {"maxResults": 50}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = cc.list_campaigns(**kwargs)
        names.extend(summary["name"] for summary in resp.get("campaignSummaryList", []))
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return names


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
