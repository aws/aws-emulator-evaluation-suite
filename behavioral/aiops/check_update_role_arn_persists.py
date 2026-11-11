"""update-role-arn-persists."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-role-arn-persists"
GROUP = "state"
SERVICES = ["aiops"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:aiops-investigation-group")
def run(ctx) -> None:
    """UpdateInvestigationGroup replaces roleArn, GetInvestigationGroup reflects the new value, and
    lastModifiedAt, a whole-second field, does not go back."""
    aiops = ctx.client("aiops")
    role_arn_1 = _create_role(ctx)
    role_arn_2 = _create_role(ctx)
    _name, arn = _create_group(ctx, aiops, role_arn_1)

    before = aiops.get_investigation_group(identifier=arn)
    assert before["roleArn"] == role_arn_1, f"expected roleArn {role_arn_1!r} right after create, got {before['roleArn']!r}"

    aiops.update_investigation_group(identifier=arn, roleArn=role_arn_2)

    after = aiops.get_investigation_group(identifier=arn)
    assert after["roleArn"] == role_arn_2, f"expected roleArn {role_arn_2!r} after update, got {after['roleArn']!r}"
    assert after["roleArn"] != role_arn_1, f"roleArn still the pre-update value {role_arn_1!r}"
    assert after["lastModifiedAt"] >= before["lastModifiedAt"], (
        f"expected lastModifiedAt at or after {before['lastModifiedAt']!r}, got {after['lastModifiedAt']!r}"
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
        Tags=[{"Key": "purpose", "Value": "sim2real"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _create_group(ctx, aiops, role_arn: str, **kwargs):
    name = ctx.unique_name("sim2real-ig-")
    kwargs.setdefault("tags", {"purpose": "sim2real"})
    deadline = time.monotonic() + 150.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = aiops.create_investigation_group(name=name, roleArn=role_arn, **kwargs)
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
