"""update-packaging-group-authorization-persists."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-packaging-group-authorization-persists"
GROUP = "state"
SERVICES = ["mediapackage-vod"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePackagingGroup persists a CDN Authorization block (secret ARN + secrets role ARN) that
    is then visible on DescribePackagingGroup, without disturbing the group's Id/Arn/DomainName."""
    mpv = ctx.client("mediapackage-vod")
    secretsmanager = ctx.client("secretsmanager")
    iam = ctx.client("iam")

    group_id = ctx.unique_name("sim2real-mpvod-group-")
    original = mpv.create_packaging_group(
        Id=group_id, Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-mpvod-group-"}
    )
    ctx.on_cleanup(lambda: mpv.delete_packaging_group(Id=group_id))

    secret_name = ctx.unique_name("sim2real-mpvod-cdnsecret-")
    secret = secretsmanager.create_secret(
        Name=secret_name,
        SecretString=json.dumps({"MediaPackageCDNIdentifier": "sim2real-cdn-token-0123456789"}),
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-mpvod-cdnsecret-"},
        ],
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(
        lambda: secretsmanager.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)
    )

    role_name = ctx.unique_name("sim2real-mpvod-secretsrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "mediapackage.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-mpvod-secretsrole-"},
        ],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "secret-access"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret_arn}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    updated = _update_group_with_retry(
        ctx, mpv, Id=group_id, Authorization={"CdnIdentifierSecret": secret_arn, "SecretsRoleArn": role_arn}
    )
    assert updated["Authorization"]["CdnIdentifierSecret"] == secret_arn, (
        f"expected UpdatePackagingGroup response CdnIdentifierSecret {secret_arn!r}, "
        f"got {updated['Authorization'].get('CdnIdentifierSecret')!r}"
    )
    assert updated["Authorization"]["SecretsRoleArn"] == role_arn, (
        f"expected UpdatePackagingGroup response SecretsRoleArn {role_arn!r}, "
        f"got {updated['Authorization'].get('SecretsRoleArn')!r}"
    )
    assert updated["Id"] == group_id, f"expected updated group Id {group_id!r}, got {updated.get('Id')!r}"
    assert updated["DomainName"] == original["DomainName"], (
        f"expected DomainName to remain {original['DomainName']!r} after UpdatePackagingGroup, "
        f"got {updated.get('DomainName')!r}"
    )

    described = mpv.describe_packaging_group(Id=group_id)
    assert described["Authorization"]["CdnIdentifierSecret"] == secret_arn, (
        f"expected DescribePackagingGroup CdnIdentifierSecret {secret_arn!r} to persist, "
        f"got {described['Authorization'].get('CdnIdentifierSecret')!r}"
    )
    assert described["Authorization"]["SecretsRoleArn"] == role_arn, (
        f"expected DescribePackagingGroup SecretsRoleArn {role_arn!r} to persist, "
        f"got {described['Authorization'].get('SecretsRoleArn')!r}"
    )


def _update_group_with_retry(ctx, mpv, timeout_s: float = 90.0, **kwargs):
    """UpdatePackagingGroup validates SecretsRoleArn and secret accessibility synchronously; retry
    past IAM trust-policy / secret-resource-policy propagation lag on a freshly created role."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return mpv.update_packaging_group(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("ForbiddenException", "UnprocessableEntityException"):
                last_err = e
                time.sleep(3.0)
                continue
            raise
    raise last_err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
