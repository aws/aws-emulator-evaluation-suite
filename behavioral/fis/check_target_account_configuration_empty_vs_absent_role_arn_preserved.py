"""target-account-configuration-empty-vs-absent-role-arn-preserved."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "target-account-configuration-empty-vs-absent-role-arn-preserved"
GROUP = "representation"
SERVICES = ["fis"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTargetAccountConfiguration returns a supplied non-empty description byte for byte, and returns no description
    key both for an omitted description and for an empty-string one."""
    iam = ctx.client("iam")
    fis = ctx.client("fis")

    role_arn = _create_fis_role(ctx, iam)
    template_id = _create_template_retrying(ctx, fis, role_arn)
    ctx.on_cleanup(lambda: fis.delete_experiment_template(id=template_id))

    account_present = "111122223333"
    account_empty = "444455556666"
    account_absent = "555566667777"
    target_role_arn_present = f"arn:aws:iam::{account_present}:role/sim2real-target-role"
    target_role_arn_empty = f"arn:aws:iam::{account_empty}:role/sim2real-target-role"
    target_role_arn_absent = f"arn:aws:iam::{account_absent}:role/sim2real-target-role"

    description_value = "sim2real-real-description"
    fis.create_target_account_configuration(
        experimentTemplateId=template_id,
        accountId=account_present,
        roleArn=target_role_arn_present,
        description=description_value,
    )
    ctx.on_cleanup(
        lambda: fis.delete_target_account_configuration(experimentTemplateId=template_id, accountId=account_present)
    )

    fis.create_target_account_configuration(
        experimentTemplateId=template_id,
        accountId=account_empty,
        roleArn=target_role_arn_empty,
        description="",
    )
    ctx.on_cleanup(
        lambda: fis.delete_target_account_configuration(experimentTemplateId=template_id, accountId=account_empty)
    )

    fis.create_target_account_configuration(
        experimentTemplateId=template_id,
        accountId=account_absent,
        roleArn=target_role_arn_absent,
    )
    ctx.on_cleanup(
        lambda: fis.delete_target_account_configuration(experimentTemplateId=template_id, accountId=account_absent)
    )

    got_present = fis.get_target_account_configuration(experimentTemplateId=template_id, accountId=account_present)[
        "targetAccountConfiguration"
    ]
    got_empty = fis.get_target_account_configuration(experimentTemplateId=template_id, accountId=account_empty)[
        "targetAccountConfiguration"
    ]
    got_absent = fis.get_target_account_configuration(experimentTemplateId=template_id, accountId=account_absent)[
        "targetAccountConfiguration"
    ]

    assert got_present.get("description") == description_value, (
        f"explicit non-empty description did not round-trip: {got_present!r}"
    )
    # An empty-string description normalizes to the same absent representation as
    # omission -- FIS does not persist a distinct present-but-empty description.
    assert "description" not in got_empty, f"expected empty description normalized to absent, got {got_empty!r}"
    assert "description" not in got_absent, f"expected description absent, got {got_absent!r}"


def _create_fis_role(ctx, iam) -> str:
    name = ctx.unique_name("sim2real-fis-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "fis.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return role_arn


def _create_template_retrying(ctx, fis, role_arn: str, timeout_s: float = 30.0) -> str:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fis.create_experiment_template(
                clientToken=ctx.unique_name("sim2real-fis-tmpl-"),
                description=ctx.unique_name("sim2real-repr-fis-"),
                stopConditions=[{"source": "none"}],
                targets={},
                actions={"waitAction": {"actionId": "aws:fis:wait", "parameters": {"duration": "PT1M"}}},
                roleArn=role_arn,
                experimentOptions={"accountTargeting": "multi-account"},
            )["experimentTemplate"]["id"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            last_err = err
            time.sleep(2)
    raise last_err


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
