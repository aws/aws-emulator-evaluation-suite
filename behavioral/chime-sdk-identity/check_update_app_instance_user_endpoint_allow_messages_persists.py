"""update-app-instance-user-endpoint-allow-messages-persists."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "update-app-instance-user-endpoint-allow-messages-persists"
GROUP = "state"
SERVICES = ["chime-sdk-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAppInstanceUserEndpoint persists a new Name and AllowMessages value that
    DescribeAppInstanceUserEndpoint then reflects."""
    # chime-sdk-identity control-plane operations are exercised in us-east-1 corpus-wide.
    client = ctx.client("chime-sdk-identity", region="us-east-1")
    instance_arn = client.create_app_instance(
        Name=ctx.unique_name("sim2real-chime-ai-"),
        Metadata="",
        ClientRequestToken=uuid.uuid4().hex,
        Tags=[{"Key": "sim2real-env", "Value": "behavioral"}],
    )["AppInstanceArn"]
    ctx.on_cleanup(lambda: client.delete_app_instance(AppInstanceArn=instance_arn))

    user_arn = client.create_app_instance_user(
        AppInstanceArn=instance_arn,
        AppInstanceUserId=ctx.unique_name("user-"),
        Name="endpoint-owner",
        ClientRequestToken=uuid.uuid4().hex,
    )["AppInstanceUserArn"]

    pinpoint = ctx.client("pinpoint", region="us-east-1")
    pinpoint_app_arn = pinpoint.create_app(
        CreateApplicationRequest={"Name": ctx.unique_name("chime-endpoint-")}
    )["ApplicationResponse"]["Arn"]
    ctx.on_cleanup(lambda: pinpoint.delete_app(ApplicationId=pinpoint_app_arn.rsplit("/", 1)[-1]))

    endpoint_id = client.register_app_instance_user_endpoint(
        AppInstanceUserArn=user_arn,
        Type="GCM",
        Name="original-endpoint-name",
        ResourceArn=pinpoint_app_arn,
        EndpointAttributes={"DeviceToken": "sim2real-fake-device-token"},
        ClientRequestToken=uuid.uuid4().hex,
        AllowMessages="ALL",
    )["EndpointId"]

    before = client.describe_app_instance_user_endpoint(
        AppInstanceUserArn=user_arn, EndpointId=endpoint_id
    )["AppInstanceUserEndpoint"]
    assert before["AllowMessages"] == "ALL", f"expected ALL before update, got {before['AllowMessages']!r}"

    client.update_app_instance_user_endpoint(
        AppInstanceUserArn=user_arn,
        EndpointId=endpoint_id,
        Name="renamed-endpoint",
        AllowMessages="NONE",
    )

    after = client.describe_app_instance_user_endpoint(
        AppInstanceUserArn=user_arn, EndpointId=endpoint_id
    )["AppInstanceUserEndpoint"]
    assert after["AllowMessages"] == "NONE", f"expected NONE after update, got {after['AllowMessages']!r}"
    assert after["Name"] == "renamed-endpoint", f"expected renamed Name to persist, got {after['Name']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
