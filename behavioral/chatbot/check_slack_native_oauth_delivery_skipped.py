"""slack-native-oauth-delivery-skipped."""
from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "slack-native-oauth-delivery-skipped"
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
    """CreateSlackChannelConfiguration with a well-formed SlackTeamId never authorized through Slack OAuth fails
    with InvalidRequestException "Unable to create the configuration because Slack workspace <id> is not
    authorized with AWS account <account>. ...", creates no configuration, and a custom action create succeeds."""
    chatbot = ctx.client("chatbot")
    role_arn = _create_chatbot_role(ctx)
    config_name = ctx.unique_name("sim2real-slack-unauth-")
    # Well-formed per the SlackTeamId (^[0-9A-Z]{1,255}$) / SlackChannelId (^[A-Za-z0-9]+$)
    # patterns, but this workspace/channel was never granted OAuth consent to this account.
    unauthorized_team_id = "T" + uuid.uuid4().hex.upper()
    unauthorized_channel_id = "C" + uuid.uuid4().hex.upper()

    code, message = _error(
        lambda: chatbot.create_slack_channel_configuration(
            SlackTeamId=unauthorized_team_id,
            SlackChannelId=unauthorized_channel_id,
            IamRoleArn=role_arn,
            ConfigurationName=config_name,
        )
    )
    assert code == "InvalidRequestException", f"unexpected code={code!r}"
    expected = (
        f"Unable to create the configuration because Slack workspace {unauthorized_team_id} "
        f"is not authorized with AWS account {ctx.account}. See  "
        "https://docs.aws.amazon.com/chatbot/latest/adminguide/slack-setup.html#slack-client-setup"
    )
    assert message == expected, f"unexpected message={message!r}"

    # Effect absent: no channel configuration was actually created for the rejected call.
    listing = chatbot.describe_slack_channel_configurations()["SlackChannelConfigurations"]
    assert not any(c["ConfigurationName"] == config_name for c in listing)
    assert not any(c["SlackTeamId"] == unauthorized_team_id for c in listing)

    # Positive control: a normal, well-formed Chatbot resource creation still succeeds,
    # proving the rejection above is specific to the unauthorized-workspace condition
    # and not a broken credential setup.
    action_arn = chatbot.create_custom_action(
        ActionName=ctx.unique_name("sim2real-ca-"),
        Definition={"CommandText": "echo control"},
        Tags=[{"TagKey": "sim2real", "TagValue": "true"}],
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
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return role["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

