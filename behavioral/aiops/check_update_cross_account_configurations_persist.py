"""update-cross-account-configurations-persist."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-cross-account-configurations-persist"
GROUP = "state"
SERVICES = ["aiops"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:aiops-investigation-group")
def run(ctx) -> None:
    """UpdateInvestigationGroup persists a crossAccountConfigurations sourceRoleArn from another
    account but refuses one from the group's own account with ValidationException and the exact
    message, leaving the configuration unchanged."""
    aiops = ctx.client("aiops")
    sts = ctx.client("sts")
    role_arn = _create_role(ctx)
    same_account_source_role_arn = _create_role(ctx)
    _name, arn = _create_group(ctx, aiops, role_arn)

    before = aiops.get_investigation_group(identifier=arn)
    assert before.get("crossAccountConfigurations", []) == []

    own_account = sts.get_caller_identity()["Account"]
    foreign_account = "111111111111" if own_account != "111111111111" else "222222222222"
    foreign_source_role_arn = f"arn:aws:iam::{foreign_account}:role/sim2real-foreign-role"

    # Positive control: a sourceRoleArn from a genuinely different account is accepted and persists.
    aiops.update_investigation_group(
        identifier=arn,
        crossAccountConfigurations=[{"sourceRoleArn": foreign_source_role_arn}],
    )
    accepted = aiops.get_investigation_group(identifier=arn)
    assert accepted.get("crossAccountConfigurations") == [
        {"sourceRoleArn": foreign_source_role_arn}
    ], accepted.get("crossAccountConfigurations")

    code, message = _error(
        lambda: aiops.update_investigation_group(
            identifier=arn,
            crossAccountConfigurations=[{"sourceRoleArn": same_account_source_role_arn}],
        )
    )
    assert code == "ValidationException", code
    expected = (
        f"Source role ARN cannot belong to the investigation account {own_account}. "
        f"Found ARN: {same_account_source_role_arn}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the rejected update did not mutate crossAccountConfigurations away from the
    # value the positive control established.
    after = aiops.get_investigation_group(identifier=arn)
    assert after.get("crossAccountConfigurations") == accepted.get("crossAccountConfigurations")


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


def _error(fn):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-aiops-role-")
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST_POLICY)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


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
                last_exc = exc
                time.sleep(5.0)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
