"""create-tag-key-boundaries-persist."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-tag-key-boundaries-persist"
GROUP = "state"
SERVICES = ["aiops"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:aiops-investigation-group")
def run(ctx) -> None:
    """tagKeyBoundaries supplied on create is persisted and returned verbatim by GetInvestigationGroup."""
    aiops = ctx.client("aiops")
    role_arn = _create_role(ctx)
    _name, arn = _create_group(ctx, aiops, role_arn, tagKeyBoundaries=["env", "service"])

    # CreateInvestigationGroup's synchronous response can momentarily race ahead of the
    # backend record actually becoming readable via GetInvestigationGroup(identifier=arn).
    got = _wait_until_visible(aiops, arn)
    assert set(got["tagKeyBoundaries"]) == {"env", "service"}, (
        f"expected tagKeyBoundaries={{'env', 'service'}}, got {set(got.get('tagKeyBoundaries', []))!r}"
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


def _wait_until_visible(aiops, arn: str, timeout_s: float = 20.0):
    """CreateInvestigationGroup's synchronous response can momentarily race ahead of the
    backend record actually becoming readable; poll GetInvestigationGroup until it 404s no
    more, so the tagKeyBoundaries assertion isn't racing create's own propagation."""
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
            resp = aiops.create_investigation_group(
                name=name, roleArn=role_arn, tags={"purpose": "sim2real"}, **kwargs
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
