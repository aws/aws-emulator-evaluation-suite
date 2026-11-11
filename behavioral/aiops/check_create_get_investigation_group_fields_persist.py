"""create-get-investigation-group-fields-persist."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-get-investigation-group-fields-persist"
GROUP = "state"
SERVICES = ["aiops"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:aiops-investigation-group")
def run(ctx) -> None:
    """CreateInvestigationGroup persists name/roleArn/retention/cloudtrail flag, readable via GetInvestigationGroup."""
    aiops = ctx.client("aiops")
    role_arn = _create_role(ctx)
    name, arn = _create_group(
        ctx,
        aiops,
        role_arn,
        retentionInDays=14,
        isCloudTrailEventHistoryEnabled=False,
        tags={"purpose": "sim2real"},
    )
    # CreateInvestigationGroup's synchronous response can momentarily race ahead of the
    # backend record actually becoming readable via GetInvestigationGroup(identifier=arn).
    got = _wait_until_visible(aiops, arn)
    assert got["name"] == name, f"expected name={name!r}, got {got['name']!r}"
    assert got["arn"] == arn, f"expected arn={arn!r}, got {got['arn']!r}"
    assert got["roleArn"] == role_arn, f"expected roleArn={role_arn!r}, got {got['roleArn']!r}"
    assert got["retentionInDays"] == 14, f"expected retentionInDays=14, got {got['retentionInDays']!r}"
    assert got["isCloudTrailEventHistoryEnabled"] is False, (
        f"expected isCloudTrailEventHistoryEnabled=False, got {got['isCloudTrailEventHistoryEnabled']!r}"
    )
    assert re.match(r"^arn:aws[a-z-]*:aiops:[a-z0-9-]*:\d{12}:investigation-group/[A-Za-z0-9]{16}$", arn), (
        f"arn does not match expected investigation-group shape: {arn!r}"
    )
    assert got.get("createdBy"), f"expected a non-empty createdBy, got {got.get('createdBy')!r}"


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


def _wait_until_visible(aiops, arn: str, timeout_s: float = 20.0):
    """CreateInvestigationGroup's synchronous response can momentarily race ahead of the
    backend record actually becoming readable; poll GetInvestigationGroup until it 404s no
    more, so the field-persistence assertions aren't racing create's own propagation."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return aiops.get_investigation_group(identifier=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            last_exc = exc
            time.sleep(1.5)
    raise last_exc


def _create_group(ctx, aiops, role_arn: str, **kwargs):
    name = ctx.unique_name("sim2real-ig-")
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
                # ResourceNotFoundException: freshly created IAM role may not have propagated
                # yet. ServiceQuotaExceededException: singleton per-account/Region slot may be
                # transiently held by another concurrently running check.
                last_exc = exc
                time.sleep(5.0)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
