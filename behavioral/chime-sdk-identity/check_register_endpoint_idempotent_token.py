"""register-endpoint-idempotent-token."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "register-endpoint-idempotent-token"
GROUP = "idempotency"
SERVICES = ["chime-sdk-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Replaying RegisterAppInstanceUserEndpoint with the same ClientRequestToken and identical
    parameters returns the same EndpointId instead of registering a second endpoint."""
    # chime-sdk-identity's control plane exists only in us-east-1 (and eu-central-1); pinned
    # explicitly since the runner's default region does not serve this service.
    client = ctx.client("chime-sdk-identity", region="us-east-1")
    instance_arn = client.create_app_instance(
        Name=ctx.unique_name("sim2real-chime-ai-"),
        Metadata="",
        ClientRequestToken=uuid.uuid4().hex,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
        CreateApplicationRequest={"Name": ctx.unique_name("sim2real-chime-pp-")}
    )["ApplicationResponse"]["Arn"]
    ctx.on_cleanup(
        lambda: pinpoint.delete_app(ApplicationId=pinpoint_app_arn.rsplit("/", 1)[-1])
    )

    token = uuid.uuid4().hex
    kwargs = dict(
        AppInstanceUserArn=user_arn,
        Type="GCM",
        ResourceArn=pinpoint_app_arn,
        EndpointAttributes={"DeviceToken": "sim2real-fake-device-token"},
        ClientRequestToken=token,
    )

    endpoint_id_1 = client.register_app_instance_user_endpoint(**kwargs)["EndpointId"]
    endpoint_id_2 = client.register_app_instance_user_endpoint(**kwargs)["EndpointId"]

    assert endpoint_id_1 == endpoint_id_2, (
        f"expected replaying RegisterAppInstanceUserEndpoint with the same ClientRequestToken to "
        f"return the same EndpointId, got {endpoint_id_1!r} then {endpoint_id_2!r}"
    )

    listed = client.list_app_instance_user_endpoints(AppInstanceUserArn=user_arn)["AppInstanceUserEndpoints"]
    matches = [e for e in listed if e["EndpointId"] == endpoint_id_1]
    assert len(matches) == 1, (
        f"expected exactly one endpoint {endpoint_id_1!r} in the independent list read, "
        f"found {len(matches)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
