"""update-cloudtrail-history-flag-toggle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-cloudtrail-history-flag-toggle"
GROUP = "state"
SERVICES = ["aiops"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:aiops-investigation-group")
def run(ctx) -> None:
    """UpdateInvestigationGroup can flip isCloudTrailEventHistoryEnabled from its default true to false."""
    aiops = ctx.client("aiops")
    role_arn = _create_role(ctx)
    _name, arn = _create_group(ctx, aiops, role_arn)

    before = aiops.get_investigation_group(identifier=arn)
    assert before["isCloudTrailEventHistoryEnabled"] is True, (
        f"expected default isCloudTrailEventHistoryEnabled=True, got {before['isCloudTrailEventHistoryEnabled']!r}"
    )

    aiops.update_investigation_group(identifier=arn, isCloudTrailEventHistoryEnabled=False)

    after = aiops.get_investigation_group(identifier=arn)
    assert after["isCloudTrailEventHistoryEnabled"] is False, (
        f"expected isCloudTrailEventHistoryEnabled=False after update, got {after['isCloudTrailEventHistoryEnabled']!r}"
    )


_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "aiops.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _create_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-aiops-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _create_group(ctx, aiops, role_arn: str, **kwargs):
    name = ctx.unique_name("sim2real-ig-")
    deadline = time.monotonic() + 150.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = aiops.create_investigation_group(
                name=name, roleArn=role_arn, tags={"sim2real": "true"}, **kwargs
            )
            arn = resp["arn"]
            ctx.on_cleanup(lambda a=arn: aiops.delete_investigation_group(identifier=a))
            return name, arn
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if (
                code == "ResourceNotFoundException"
                or code == "ServiceQuotaExceededException"
                or (code == "ValidationException" and "assume" in msg.lower())
            ):
                last_exc = exc
                time.sleep(5.0)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
