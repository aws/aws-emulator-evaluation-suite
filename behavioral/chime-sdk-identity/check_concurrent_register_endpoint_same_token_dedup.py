"""concurrent-register-endpoint-same-token-dedup."""
from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-register-endpoint-same-token-dedup"
GROUP = "concurrency"
SERVICES = ["chime-sdk-identity"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """8 concurrent RegisterAppInstanceUserEndpoint calls with the same ClientRequestToken and parameters return
    one single EndpointId (any other call fails with ConflictException), and ListAppInstanceUserEndpoints lists
    that endpoint exactly once."""
    # chime-sdk-identity's control plane is region-pinned to us-east-1.
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
        Name="race-endpoint-owner",
        ClientRequestToken=uuid.uuid4().hex,
        Tags=[{"Key": "sim2real-env", "Value": "behavioral"}],
    )["AppInstanceUserArn"]

    # RegisterAppInstanceUserEndpoint's ResourceArn must name a Pinpoint app the caller's own
    # account actually owns -- a syntactically well-formed but non-existent ARN is rejected with
    # ForbiddenException before any dedup logic runs, so the race has to be staged against a real one.
    own_account = ctx.client("sts").get_caller_identity()["Account"]
    pinpoint = ctx.client("pinpoint", region="us-east-1")
    pinpoint_app_id = pinpoint.create_app(
        CreateApplicationRequest={"Name": ctx.unique_name("sim2real-pp-")}
    )["ApplicationResponse"]["Id"]
    ctx.on_cleanup(lambda: pinpoint.delete_app(ApplicationId=pinpoint_app_id))

    token = uuid.uuid4().hex
    kwargs = dict(
        AppInstanceUserArn=user_arn,
        Type="GCM",
        ResourceArn=f"arn:aws:mobiletargeting:us-east-1:{own_account}:apps/{pinpoint_app_id}",
        EndpointAttributes={"DeviceToken": "sim2real-fake-device-token"},
        ClientRequestToken=token,
    )

    def racer(_):
        try:
            return ("ok", client.register_app_instance_user_endpoint(**kwargs)["EndpointId"])
        except ClientError as e:
            return ("error", e.response["Error"]["Code"], e.response["Error"]["Message"])

    n = 8
    with ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(racer, range(n)))

    ok_endpoint_ids = {r[1] for r in results if r[0] == "ok"}
    errors = [r for r in results if r[0] == "error"]

    # Every racer either got the deduped EndpointId or a well-formed conflict -- never
    # a distinct successful EndpointId.
    assert len(ok_endpoint_ids) == 1, f"idempotency token dedup broke under contention: {results}"
    for err in errors:
        assert err[1] == "ConflictException", f"unexpected error under contention: {err}"

    endpoint_id = next(iter(ok_endpoint_ids))
    listed = client.list_app_instance_user_endpoints(AppInstanceUserArn=user_arn)["AppInstanceUserEndpoints"]
    matches = [e for e in listed if e["EndpointId"] == endpoint_id]
    assert len(matches) == 1, f"expected exactly one listed endpoint {endpoint_id!r}, found {matches!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
