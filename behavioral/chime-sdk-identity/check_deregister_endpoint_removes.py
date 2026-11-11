"""deregister-endpoint-removes."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregister-endpoint-removes"
GROUP = "state"
SERVICES = ["chime-sdk-identity"]
FORBIDDEN_MESSAGE = "You are not allowed to make this request."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeregisterAppInstanceUserEndpoint removes the endpoint: it disappears from
    ListAppInstanceUserEndpoints, DescribeAppInstanceUserEndpoint starts rejecting it, and a
    mutation against the dead id is rejected the same way."""
    # chime-sdk-identity is only published in us-east-1 and eu-central-1 (botocore
    # endpoints.json); the suite's default us-west-2 does not resolve it.
    client = ctx.client("chime-sdk-identity", region="us-east-1")
    tag_list = [{"Key": "sim2real-env", "Value": "behavioral"}]
    pinpoint = ctx.client("pinpoint", region="us-east-1")
    pinpoint_app_arn = pinpoint.create_app(
        CreateApplicationRequest={"Name": ctx.unique_name("sim2real-chime-pp-")}
    )["ApplicationResponse"]["Arn"]
    ctx.on_cleanup(lambda: pinpoint.delete_app(ApplicationId=pinpoint_app_arn.rsplit("/", 1)[-1]))
    instance_arn = client.create_app_instance(
        Name=ctx.unique_name("sim2real-chime-ai-"),
        Metadata="",
        ClientRequestToken=uuid.uuid4().hex,
        Tags=tag_list,
    )["AppInstanceArn"]
    ctx.on_cleanup(lambda: client.delete_app_instance(AppInstanceArn=instance_arn))

    user_arn = client.create_app_instance_user(
        AppInstanceArn=instance_arn,
        AppInstanceUserId=ctx.unique_name("user-"),
        Name="endpoint-owner",
        ClientRequestToken=uuid.uuid4().hex,
        Tags=tag_list,
    )["AppInstanceUserArn"]

    endpoint_id = client.register_app_instance_user_endpoint(
        AppInstanceUserArn=user_arn,
        Type="APNS",
        ResourceArn=pinpoint_app_arn,
        EndpointAttributes={"DeviceToken": "sim2real-fake-device-token"},
        ClientRequestToken=uuid.uuid4().hex,
    )["EndpointId"]

    listed = client.list_app_instance_user_endpoints(AppInstanceUserArn=user_arn)["AppInstanceUserEndpoints"]
    assert any(e["EndpointId"] == endpoint_id for e in listed), (
        f"expected {endpoint_id!r} in list right after registration, got {listed!r}"
    )

    client.deregister_app_instance_user_endpoint(AppInstanceUserArn=user_arn, EndpointId=endpoint_id)

    code, message = _error(
        lambda: client.describe_app_instance_user_endpoint(
            AppInstanceUserArn=user_arn, EndpointId=endpoint_id
        )
    )
    assert code == "ForbiddenException", f"expected ForbiddenException on describe after deregister, got {code!r}"
    assert message == FORBIDDEN_MESSAGE, f"expected message {FORBIDDEN_MESSAGE!r}, got {message!r}"

    update_code, update_message = _error(
        lambda: client.update_app_instance_user_endpoint(
            AppInstanceUserArn=user_arn, EndpointId=endpoint_id, Name="post-deregister-rename"
        )
    )
    assert update_code == "ForbiddenException", (
        f"expected ForbiddenException mutating the deregistered endpoint, got {update_code!r}"
    )
    assert update_message == FORBIDDEN_MESSAGE, (
        f"expected message {FORBIDDEN_MESSAGE!r}, got {update_message!r}"
    )

    listed_after = client.list_app_instance_user_endpoints(AppInstanceUserArn=user_arn)["AppInstanceUserEndpoints"]
    assert not any(e["EndpointId"] == endpoint_id for e in listed_after), (
        f"expected {endpoint_id!r} absent from list after deregister, got {listed_after!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because a
    target accepting a call the check expects refused is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
