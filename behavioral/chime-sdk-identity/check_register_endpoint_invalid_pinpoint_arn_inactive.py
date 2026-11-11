"""register-endpoint-invalid-pinpoint-arn-inactive."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-endpoint-invalid-pinpoint-arn-inactive"
GROUP = "overly-permissive"
SERVICES = ["chime-sdk-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterAppInstanceUserEndpoint with a well-formed ResourceArn naming a nonexistent Pinpoint app in the
    caller's account fails with ForbiddenException "You are not authorized to perform this action." and creates
    no endpoint, while the same call on a real Pinpoint app creates an ACTIVE endpoint."""
    # chime-sdk-identity's control plane is us-east-1 only. Pinpoint's control plane also
    # runs in us-east-1 here so both ARNs share one partition/region.
    client = ctx.client("chime-sdk-identity", region="us-east-1")
    pinpoint = ctx.client("pinpoint", region="us-east-1")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

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

    # Positive control: a REAL Pinpoint app, so the same call shape must succeed.
    real_app_id = pinpoint.create_app(
        CreateApplicationRequest={"Name": ctx.unique_name("sim2real-pp-")}
    )["ApplicationResponse"]["Id"]
    ctx.on_cleanup(lambda: pinpoint.delete_app(ApplicationId=real_app_id))
    real_arn = f"arn:aws:mobiletargeting:us-east-1:{account_id}:apps/{real_app_id}"
    good_endpoint_id = client.register_app_instance_user_endpoint(
        AppInstanceUserArn=user_arn,
        Type="GCM",
        ResourceArn=real_arn,
        EndpointAttributes={"DeviceToken": "sim2real-fake-device-token"},
        ClientRequestToken=uuid.uuid4().hex,
    )["EndpointId"]
    good_desc = client.describe_app_instance_user_endpoint(
        AppInstanceUserArn=user_arn, EndpointId=good_endpoint_id
    )["AppInstanceUserEndpoint"]
    assert good_desc["EndpointState"]["Status"] == "ACTIVE", (
        f"positive control against a real Pinpoint app did not land ACTIVE: "
        f"{good_desc['EndpointState']!r}"
    )

    # Break exactly one thing: same shape, same account/region, but an app id that was never
    # created. The ARN passes botocore's local ChimeArn pattern check, so any refusal below is a
    # SERVER decision, not a client-side ParamValidationError.
    fake_arn = f"arn:aws:mobiletargeting:us-east-1:{account_id}:apps/{uuid.uuid4().hex[:26]}"

    def _register_fake():
        return client.register_app_instance_user_endpoint(
            AppInstanceUserArn=user_arn,
            Type="GCM",
            ResourceArn=fake_arn,
            EndpointAttributes={"DeviceToken": "sim2real-fake-device-token"},
            ClientRequestToken=uuid.uuid4().hex,
        )

    try:
        result = _register_fake()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(
            f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}"
        )
    assert code == "ForbiddenException", (
        f"expected ForbiddenException for a nonexistent-but-correctly-scoped Pinpoint ARN, "
        f"got {code!r}"
    )
    assert message == "You are not authorized to perform this action.", (
        f"expected the exact ForbiddenException message, got {message!r}"
    )

    # Effect absent, via an independent read: the refused call must not have materialized an
    # endpoint at all -- only the positive control's endpoint exists under this user.
    endpoints_after = client.list_app_instance_user_endpoints(AppInstanceUserArn=user_arn)[
        "AppInstanceUserEndpoints"
    ]
    endpoint_ids_after = {e["EndpointId"] for e in endpoints_after}
    assert endpoint_ids_after == {good_endpoint_id}, (
        f"the refused register call left {endpoint_ids_after!r} under the user; expected only "
        f"the positive control's endpoint {good_endpoint_id!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
