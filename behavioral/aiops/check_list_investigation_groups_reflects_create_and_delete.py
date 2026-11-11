"""list-investigation-groups-reflects-create-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-investigation-groups-reflects-create-and-delete"
GROUP = "list"
SERVICES = ["aiops"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:aiops-investigation-group")
def run(ctx) -> None:
    """ListInvestigationGroups shows the created group (only one is allowed per account/Region) and stops showing it after delete."""
    aiops = ctx.client("aiops")
    _delete_leaked_groups(aiops)

    role_arn = _create_role(ctx)
    name, arn = _create_group(ctx, aiops, role_arn)

    listed = aiops.list_investigation_groups(maxResults=50)["investigationGroups"]
    assert len(listed) == 1, f"expected exactly 1 investigation group listed after create, got {len(listed)}: {listed}"
    assert listed[0]["arn"] == arn, f"expected listed arn {arn!r}, got {listed[0]['arn']!r}"
    assert listed[0]["name"] == name, f"expected listed name {name!r}, got {listed[0]['name']!r}"

    aiops.delete_investigation_group(identifier=arn)

    listed_after = aiops.list_investigation_groups(maxResults=50)["investigationGroups"]
    assert listed_after == [], f"expected list empty after delete, got {listed_after}"


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


def _delete_leaked_groups(aiops) -> None:
    try:
        resp = aiops.list_investigation_groups(maxResults=50)
    except ClientError:
        return
    for group in resp.get("investigationGroups", []):
        if group.get("name", "").startswith("sim2real-"):
            try:
                aiops.delete_investigation_group(identifier=group["arn"])
            except ClientError:
                pass


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
