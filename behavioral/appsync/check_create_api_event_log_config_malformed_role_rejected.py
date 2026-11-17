"""create-api-event-log-config-malformed-role-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-api-event-log-config-malformed-role-rejected"
GROUP = "event-api"
SERVICES = ["appsync", "iam"]

_EVENT_CONFIG = {
    "authProviders": [{"authType": "API_KEY"}],
    "connectionAuthModes": [{"authType": "API_KEY"}],
    "defaultPublishAuthModes": [{"authType": "API_KEY"}],
    "defaultSubscribeAuthModes": [{"authType": "API_KEY"}],
}


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApi with an Event API eventConfig.logConfig.cloudWatchLogsRoleArn that is not a
    well-formed role ARN fails BadRequestException and creates no Api; a real role ARN succeeds."""
    appsync = ctx.client("appsync")
    iam = ctx.client("iam")

    bad_name = ctx.unique_name("sim2real-eventapi-logcfg-bad-")
    bad_event_config = dict(
        _EVENT_CONFIG, logConfig={"logLevel": "ERROR", "cloudWatchLogsRoleArn": "not-a-valid-arn"}
    )
    code, message = _error(
        lambda: appsync.create_api(name=bad_name, eventConfig=bad_event_config)
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == (
        "The cloudWatchLogsRoleArn is invalid. Please refer to the documentation for more details."
    ), f"expected the exact refusal message, got {message!r}"

    apis = appsync.list_apis()["apis"]
    assert all(a["name"] != bad_name for a in apis), (
        f"rejected CreateApi must not create an Api: found {bad_name!r} in ListApis"
    )

    role_name = ctx.unique_name("sim2real-eventapi-logs-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "appsync.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    good_name = ctx.unique_name("sim2real-eventapi-logcfg-good-")
    good_event_config = dict(
        _EVENT_CONFIG, logConfig={"logLevel": "ERROR", "cloudWatchLogsRoleArn": role_arn}
    )
    created = appsync.create_api(name=good_name, eventConfig=good_event_config)["api"]
    api_id = created["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_api(apiId=api_id))
    assert created["eventConfig"]["logConfig"]["cloudWatchLogsRoleArn"] == role_arn, (
        f"expected logConfig.cloudWatchLogsRoleArn {role_arn!r}, got {created['eventConfig'].get('logConfig')!r}"
    )

    fetched = appsync.get_api(apiId=api_id)["api"]
    assert fetched["eventConfig"]["logConfig"]["cloudWatchLogsRoleArn"] == role_arn, (
        f"independent read: expected cloudWatchLogsRoleArn {role_arn!r}, "
        f"got {fetched['eventConfig'].get('logConfig')!r}"
    )
    assert fetched["eventConfig"]["logConfig"]["logLevel"] == "ERROR", (
        f"independent read: expected logLevel 'ERROR', got {fetched['eventConfig'].get('logConfig')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
