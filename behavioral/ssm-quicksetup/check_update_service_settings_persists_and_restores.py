"""update-service-settings-persists-and-restores."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-service-settings-persists-and-restores"
GROUP = "settings"
SERVICES = ["ssm-quicksetup"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ssm-quicksetup-service-settings")
def run(ctx) -> None:
    """UpdateServiceSettings sets ExplorerEnablingRoleArn and GetServiceSettings returns that role ARN right after;
    the previous value is restored on cleanup."""
    qs = ctx.client("ssm-quicksetup")
    iam = ctx.client("iam")

    original = qs.get_service_settings()["ServiceSettings"].get("ExplorerEnablingRoleArn")

    role_name = ctx.unique_name("sim2real-qs-explorer-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ssm.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-qs-explorer"}],
    )["Role"]["Arn"]

    def _restore():
        if original is not None:
            qs.update_service_settings(ExplorerEnablingRoleArn=original)
        # if there was no original value we intentionally leave the (harmless, unbilled) IAM
        # role in place rather than pointing the account setting at a deleted role.
        else:
            return
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_restore)

    # UpdateServiceSettings can reject a just-created role until IAM propagation catches up, so
    # poll the mutating call itself to a bounded deadline rather than sleeping a fixed duration.
    deadline = time.monotonic() + 60
    applied = False
    last_code = None
    while time.monotonic() < deadline:
        try:
            qs.update_service_settings(ExplorerEnablingRoleArn=role_arn)
            applied = True
            break
        except ClientError as e:
            last_code = e.response["Error"]["Code"]
            time.sleep(3)
    assert applied, (
        f"UpdateServiceSettings never accepted the newly created role within the IAM "
        f"eventual-consistency window (last error: {last_code})"
    )

    got = qs.get_service_settings()["ServiceSettings"]
    assert got.get("ExplorerEnablingRoleArn") == role_arn, (
        f"GetServiceSettings did not reflect the role just set via UpdateServiceSettings: "
        f"expected {role_arn!r}, got {got.get('ExplorerEnablingRoleArn')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
