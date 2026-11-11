"""teams-channel-invalid-team-id-uuid-rejected."""
from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "teams-channel-invalid-team-id-uuid-rejected"
GROUP = "overly-permissive"
SERVICES = ["chatbot"]


def _error(fn):
    """Call fn(); return the (code, message) it is refused with. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateMicrosoftTeamsChannelConfiguration with a 36-character non-UUID TeamId fails with
    InvalidRequestException "Invalid request body", a well-formed unauthorized TeamId with "The team id you are
    using is not configured in this account", neither creates a configuration, and a custom action create succeeds."""
    chatbot = ctx.client("chatbot")
    role_arn = _create_chatbot_role(ctx)
    config_name = ctx.unique_name("sim2real-teams-bad-")
    bad_team_id = "1" * 36  # right length (36), wrong shape (no hyphens / not hex-UUID)
    tenant_id = str(uuid.uuid4())
    channel_id = f"19%3a{ctx.unique_name('c')}%40thread.v2"

    code, message = _error(
        lambda: chatbot.create_microsoft_teams_channel_configuration(
            ChannelId=channel_id,
            TeamId=bad_team_id,
            TenantId=tenant_id,
            IamRoleArn=role_arn,
            ConfigurationName=config_name,
        )
    )
    assert code == "InvalidRequestException", f"malformed code={code!r} message={message!r}"
    assert message == "Invalid request body", (
        f"malformed TeamId message did not read as a shape-validation refusal: {message!r}"
    )

    listing = chatbot.list_microsoft_teams_channel_configurations()["TeamChannelConfigurations"]
    assert not any(c.get("ConfigurationName") == config_name for c in listing)

    # Discriminator: a well-formed-but-unauthorized TeamId hits the SAME error code but
    # a DIFFERENT, more specific message -- proving the malformed-shape rejection above
    # is not simply "the account has no configured teams at all" wearing a shared code.
    wf_config_name = ctx.unique_name("sim2real-teams-wf-")
    wf_code, wf_message = _error(
        lambda: chatbot.create_microsoft_teams_channel_configuration(
            ChannelId=channel_id,
            TeamId=str(uuid.uuid4()),
            TenantId=tenant_id,
            IamRoleArn=role_arn,
            ConfigurationName=wf_config_name,
        )
    )
    assert wf_code == "InvalidRequestException", f"well-formed-unauthorized code={wf_code!r} message={wf_message!r}"
    assert wf_message == "The team id you are using is not configured in this account", (
        f"well-formed-unauthorized message did not read as a team-not-configured refusal: {wf_message!r}"
    )
    assert wf_message != message, "well-formed-unauthorized TeamId must not read as a shape refusal"

    listing = chatbot.list_microsoft_teams_channel_configurations()["TeamChannelConfigurations"]
    assert not any(c.get("ConfigurationName") == wf_config_name for c in listing)

    # Positive control: the credentials and service are otherwise fully functional --
    # a normal, well-formed Chatbot resource creation succeeds.
    action_arn = chatbot.create_custom_action(
        ActionName=ctx.unique_name("sim2real-ca-"),
        Definition={"CommandText": "echo control"},
        Tags=[{"TagKey": "sim2real-check", "TagValue": CHECK}],
    )["CustomActionArn"]
    ctx.on_cleanup(lambda: chatbot.delete_custom_action(CustomActionArn=action_arn))
    got = chatbot.get_custom_action(CustomActionArn=action_arn)["CustomAction"]
    assert got["CustomActionArn"] == action_arn


def _create_chatbot_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-chatbot-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "chatbot.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return role["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
