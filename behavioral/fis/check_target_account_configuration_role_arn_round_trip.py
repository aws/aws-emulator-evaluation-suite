"""target-account-configuration-role-arn-round-trip."""
from __future__ import annotations

import json
import string
import time
from typing import Any

from behavioral_harness import tags

CHECK = "target-account-configuration-role-arn-round-trip"
GROUP = "representation"
SERVICES = ["fis"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A long (multi-segment IAM path), non-trivial roleArn, written via
    CreateTargetAccountConfiguration, is returned byte-identical by
    GetTargetAccountConfiguration (no truncation, normalization, or case-folding)."""
    fis = ctx.client("fis")
    role_arn = _create_orchestrator_role(ctx)
    template_id = _create_wait_template(
        ctx, role_arn, experiment_options={"accountTargeting": "multi-account"}
    )

    account_id = "111122223333"
    target_role_arn = _max_length_role_arn(account_id)
    assert len(target_role_arn) > 250, (
        f"expected the constructed roleArn to exceed 250 chars, got length {len(target_role_arn)}"
    )

    fis.create_target_account_configuration(
        experimentTemplateId=template_id,
        accountId=account_id,
        clientToken=ctx.unique_name("sim2real-fis-tac-"),
        roleArn=target_role_arn,
        description="edge-case roleArn round trip",
    )
    ctx.on_cleanup(
        lambda: fis.delete_target_account_configuration(
            experimentTemplateId=template_id, accountId=account_id
        )
    )

    got = fis.get_target_account_configuration(
        experimentTemplateId=template_id, accountId=account_id
    )["targetAccountConfiguration"]
    assert got["roleArn"] == target_role_arn, (
        f"expected byte-identical roleArn {target_role_arn!r}, got {got.get('roleArn')!r}"
    )
    assert len(got["roleArn"]) > 250, (
        f"expected the round-tripped roleArn to stay over 250 chars, got length {len(got['roleArn'])}"
    )
    assert got["accountId"] == account_id, (
        f"expected accountId {account_id!r}, got {got.get('accountId')!r}"
    )


def _max_length_role_arn(account_id: str) -> str:
    """Build a long, multi-segment IAM role ARN: several /-separated path segments
    (mirrors a real IAM role path) each well under IAM's 64-char role-name limit,
    since FIS's ARN-shape validation appears to apply that same limit to the
    trailing "role name" segment even though the roleArn field itself allows up
    to 1224 characters overall."""
    prefix = f"arn:aws:iam::{account_id}:role/"
    charset = string.ascii_letters + string.digits + "+=,.@_-"
    segment_len = 32
    n_segments = 8
    total_needed = segment_len * n_segments
    pool = charset * (total_needed // len(charset) + 2)
    segments = [pool[i * segment_len : (i + 1) * segment_len] for i in range(n_segments)]
    return prefix + "/".join(segments)


def _create_orchestrator_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-fis-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "fis.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "g1-fault-injection"}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role["Arn"]


def _create_wait_template(
    ctx, role_arn: str, experiment_options: dict[str, Any] | None = None
) -> str:
    fis = ctx.client("fis")
    kwargs: dict[str, Any] = dict(
        clientToken=ctx.unique_name("sim2real-fis-tmpl-"),
        description="sim2real fis behavioral check template",
        stopConditions=[{"source": "none"}],
        actions={
            "wait1": {"actionId": "aws:fis:wait", "parameters": {"duration": "PT1M"}}
        },
        targets={},
        roleArn=role_arn,
    )
    if experiment_options:
        kwargs["experimentOptions"] = experiment_options

    # A freshly created IAM role can take a few seconds to propagate before FIS can
    # resolve/assume it (IAM's documented eventual-consistency window for a new
    # role). Poll CreateExperimentTemplate until the role is recognized.
    deadline = time.monotonic() + 30
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            template_id = fis.create_experiment_template(**kwargs)["experimentTemplate"]["id"]
            ctx.on_cleanup(lambda: fis.delete_experiment_template(id=template_id))
            return template_id
        except Exception as err:  # noqa: BLE001
            code = getattr(err, "response", {}).get("Error", {}).get("Code")
            if code != "ResourceNotFoundException":
                raise
            last_err = err
            time.sleep(2)
    raise AssertionError(f"role never became usable by FIS: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


