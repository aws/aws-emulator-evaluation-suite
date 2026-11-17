"""create-graphql-api-malformed-cloudwatch-logs-role-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-graphql-api-malformed-cloudwatch-logs-role-rejected"
GROUP = "graphql-api"
SERVICES = ["appsync", "iam"]


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
    """CreateGraphqlApi with a logConfig.cloudWatchLogsRoleArn that is not a well-formed role ARN
    fails BadRequestException and creates no API; a real role ARN succeeds."""
    appsync = ctx.client("appsync")
    iam = ctx.client("iam")

    bad_name = ctx.unique_name("sim2real-behav-logcfg-bad-")
    bad_log_config = {"fieldLogLevel": "ERROR", "cloudWatchLogsRoleArn": "not-a-valid-arn"}
    code, message = _error(
        lambda: appsync.create_graphql_api(
            name=bad_name, authenticationType="API_KEY", logConfig=bad_log_config
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == (
        "The cloudWatchLogsRoleArn is invalid. Please refer to the documentation for more details."
    ), f"expected the exact refusal message, got {message!r}"

    apis = appsync.list_graphql_apis()["graphqlApis"]
    assert all(a["name"] != bad_name for a in apis), (
        f"rejected CreateGraphqlApi must not create an API: found {bad_name!r} in ListGraphqlApis"
    )

    role_name = ctx.unique_name("sim2real-appsync-logs-role-")
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

    good_name = ctx.unique_name("sim2real-behav-logcfg-good-")
    good_log_config = {"fieldLogLevel": "ERROR", "cloudWatchLogsRoleArn": role_arn}
    created = appsync.create_graphql_api(
        name=good_name, authenticationType="API_KEY", logConfig=good_log_config
    )["graphqlApi"]
    api_id = created["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    assert created["logConfig"]["cloudWatchLogsRoleArn"] == role_arn, (
        f"expected logConfig.cloudWatchLogsRoleArn {role_arn!r}, got {created.get('logConfig')!r}"
    )

    fetched = appsync.get_graphql_api(apiId=api_id)["graphqlApi"]
    assert fetched["logConfig"]["cloudWatchLogsRoleArn"] == role_arn, (
        f"independent read: expected cloudWatchLogsRoleArn {role_arn!r}, got {fetched.get('logConfig')!r}"
    )
    assert fetched["logConfig"]["fieldLogLevel"] == "ERROR", (
        f"independent read: expected fieldLogLevel 'ERROR', got {fetched.get('logConfig')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
