"""concurrent-create-app-instance-admin-race."""
from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-app-instance-admin-race"
GROUP = "concurrency"
SERVICES = ["chime-sdk-identity"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """8 concurrent CreateAppInstanceAdmin calls promoting the same user succeed at least once, every other call
    fails with ConflictException, and ListAppInstanceAdmins lists that user exactly once."""
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
        Name="race-admin-candidate",
        ClientRequestToken=uuid.uuid4().hex,
    )["AppInstanceUserArn"]

    def racer(_):
        try:
            client.create_app_instance_admin(AppInstanceAdminArn=user_arn, AppInstanceArn=instance_arn)
            return ("ok", None)
        except ClientError as e:
            return ("error", e.response["Error"]["Code"])

    n = 8
    with ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(racer, range(n)))

    oks = [r for r in results if r[0] == "ok"]
    errors = [r[1] for r in results if r[0] == "error"]

    assert len(oks) >= 1, f"no racer succeeded in promoting the identity: {results}"
    for err in errors:
        assert err == "ConflictException", f"unexpected error under contention: {err}"

    admins = client.list_app_instance_admins(AppInstanceArn=instance_arn)["AppInstanceAdmins"]
    matches = [a for a in admins if a["Admin"]["Arn"] == user_arn]
    assert len(matches) == 1, f"expected exactly one admin grant, found {len(matches)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
