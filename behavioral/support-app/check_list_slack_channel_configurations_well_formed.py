"""list-slack-channel-configurations-well-formed."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-slack-channel-configurations-well-formed"
GROUP = "control-plane"
SERVICES = ["support-app"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSlackChannelConfigurations returns a list whose entries carry non-empty teamId and channelId
    and correctly typed optional fields, and an empty list carries no nextToken."""
    client = ctx.client("support-app")

    resp = client.list_slack_channel_configurations()
    configs = resp.get("slackChannelConfigurations")
    assert isinstance(configs, list), f"expected a list, got {type(configs).__name__}"

    for cfg in configs:
        # teamId/channelId are the only required members of SlackChannelConfiguration.
        assert isinstance(cfg.get("teamId"), str) and cfg["teamId"], f"bad teamId: {cfg.get('teamId')!r}"
        assert isinstance(cfg.get("channelId"), str) and cfg["channelId"], (
            f"bad channelId: {cfg.get('channelId')!r}"
        )
        if "channelName" in cfg:
            assert isinstance(cfg["channelName"], str), f"channelName not str: {cfg['channelName']!r}"
        for flag in (
            "notifyOnCreateOrReopenCase",
            "notifyOnAddCorrespondenceToCase",
            "notifyOnResolveCase",
        ):
            if flag in cfg:
                assert isinstance(cfg[flag], bool), f"{flag} not bool: {cfg[flag]!r}"
        if "channelRoleArn" in cfg:
            assert cfg["channelRoleArn"].startswith("arn:aws:iam::"), (
                f"channelRoleArn not an IAM role ARN: {cfg['channelRoleArn']!r}"
            )

    # Documented pagination contract: "When the API returns the last set of
    # results, the response doesn't include a pagination token value." An
    # empty list is necessarily the last (and only) page.
    if not configs:
        assert "nextToken" not in resp, f"nextToken present on an empty, terminal page: {resp!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
