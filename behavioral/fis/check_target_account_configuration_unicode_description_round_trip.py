"""target-account-configuration-unicode-description-round-trip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "target-account-configuration-unicode-description-round-trip"
GROUP = "representation"
SERVICES = ["fis"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A unicode/emoji target-account-configuration description round-trips byte-identical."""
    iam = ctx.client("iam")
    fis = ctx.client("fis")

    role_arn = _create_fis_role(ctx, iam)
    template_id = _create_template_retrying(ctx, fis, role_arn)
    ctx.on_cleanup(lambda: fis.delete_experiment_template(id=template_id))

    account_id = "111122223333"
    target_role_arn = f"arn:aws:iam::{account_id}:role/sim2real-target-role"
    description = "Fault injection déscription \U0001f680 ünïcode ⚡ 测试 テスト"

    fis.create_target_account_configuration(
        experimentTemplateId=template_id,
        accountId=account_id,
        roleArn=target_role_arn,
        description=description,
    )
    ctx.on_cleanup(
        lambda: fis.delete_target_account_configuration(experimentTemplateId=template_id, accountId=account_id)
    )

    got = fis.get_target_account_configuration(experimentTemplateId=template_id, accountId=account_id)[
        "targetAccountConfiguration"
    ]
    assert got["description"] == description, f"expected description {description!r}, got {got['description']!r}"
    assert got["roleArn"] == target_role_arn, f"expected roleArn {target_role_arn!r}, got {got['roleArn']!r}"
    assert got["accountId"] == account_id, f"expected accountId {account_id!r}, got {got['accountId']!r}"


def _create_fis_role(ctx, iam) -> str:
    name = ctx.unique_name("sim2real-fis-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "fis.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "g1-fault-injection"}],
    )["Role"]["Arn"]
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
                tags={"sim2real-check": CHECK},
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
