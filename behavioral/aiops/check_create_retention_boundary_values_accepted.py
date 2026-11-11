"""create-retention-boundary-values-accepted."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-retention-boundary-values-accepted"
GROUP = "state"
SERVICES = ["aiops"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:aiops-investigation-group")
def run(ctx) -> None:
    """retentionInDays at its documented boundaries (7 and 90) is accepted and stored verbatim, not silently clamped."""
    aiops = ctx.client("aiops")
    role_arn = _create_role(ctx)

    _name_low, arn_low = _create_group(ctx, aiops, role_arn, retentionInDays=7)
    got_low = aiops.get_investigation_group(identifier=arn_low)
    assert got_low["retentionInDays"] == 7, f"expected retentionInDays=7, got {got_low['retentionInDays']!r}"
    # aiops enforces one investigation group per account/Region, so this group must be gone before
    # the second boundary value can be created.
    aiops.delete_investigation_group(identifier=arn_low)
    _wait_until_gone(aiops, arn_low)

    _name_high, arn_high = _create_group(ctx, aiops, role_arn, retentionInDays=90)
    got_high = aiops.get_investigation_group(identifier=arn_high)
    assert got_high["retentionInDays"] == 90, f"expected retentionInDays=90, got {got_high['retentionInDays']!r}"


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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _create_group(ctx, aiops, role_arn: str, **kwargs):
    name = ctx.unique_name("sim2real-ig-")
    kwargs.setdefault("tags", {"sim2real": CHECK})
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


def _wait_until_gone(aiops, arn: str, timeout_s: float = 20.0) -> None:
    """Delete's own response can race ahead of the backend record actually disappearing;
    poll GetInvestigationGroup until it 404s so the singleton slot is provably free."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            aiops.get_investigation_group(identifier=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(1.5)
    raise AssertionError(f"investigation group {arn} still visible {timeout_s}s after delete")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
