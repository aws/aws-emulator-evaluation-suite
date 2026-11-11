"""list-target-account-configurations-pagination-covers-all-accounts."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "list-target-account-configurations-pagination-covers-all-accounts"
GROUP = "data-plane"
SERVICES = ["fis"]

# Documentation placeholder accounts: FIS stores the configurations and contacts none of them.
_PLACEHOLDER_ACCOUNTS = (
    "111122223333", "444455556666", "555566667777", "777788889999", "222233334444",
    "888899990000", "999900001111",
)
_NUM_ACCOUNTS = len(_PLACEHOLDER_ACCOUNTS)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:fis-active-experiment-quota")
def run(ctx) -> None:
    """Paginated ListTargetAccountConfigurations returns every configuration exactly once, and
    ListExperimentTargetAccountConfigurations shows the same set for an experiment started from it."""
    iam = ctx.client("iam")
    fis = ctx.client("fis")

    role_arn = _create_fis_role(ctx, iam)
    template_id = _create_template_retrying(ctx, fis, role_arn)
    ctx.on_cleanup(lambda: fis.delete_experiment_template(id=template_id))

    account_ids = list(_PLACEHOLDER_ACCOUNTS)
    for account_id in account_ids:
        target_role_arn = f"arn:aws:iam::{account_id}:role/sim2real-target-role"
        fis.create_target_account_configuration(
            experimentTemplateId=template_id, accountId=account_id, roleArn=target_role_arn
        )
        ctx.on_cleanup(
            lambda a=account_id: fis.delete_target_account_configuration(
                experimentTemplateId=template_id, accountId=a
            )
        )

    seen: list[str] = []
    page_sizes: list[int] = []
    next_token = None
    while True:
        kwargs = {"experimentTemplateId": template_id, "maxResults": 2}
        if next_token:
            kwargs["nextToken"] = next_token
        page = fis.list_target_account_configurations(**kwargs)
        page_items = page["targetAccountConfigurations"]
        assert len(page_items) <= 2, f"page respected maxResults=2 but returned {len(page_items)} items: {page_items}"
        page_sizes.append(len(page_items))
        seen.extend(c["accountId"] for c in page_items)
        next_token = page.get("nextToken")
        if not next_token:
            break

    assert len(page_sizes) > 1, (
        f"expected {_NUM_ACCOUNTS} accounts with maxResults=2 to require multiple pages, "
        f"got a single page of {page_sizes}: a target that ignores maxResults would pass this "
        f"check just as well as one that paginates correctly"
    )
    assert sorted(seen) == sorted(account_ids), f"pagination mismatch: {sorted(seen)} != {sorted(account_ids)}"
    assert len(seen) == len(set(seen)), f"pagination produced duplicates: {seen}"

    experiment_id = _start_experiment_retrying(ctx, fis, template_id)
    ctx.on_cleanup(lambda: _stop_experiment_quiet(fis, experiment_id))

    exp_seen: list[str] = []
    next_token = None
    while True:
        kwargs = {"experimentId": experiment_id}
        if next_token:
            kwargs["nextToken"] = next_token
        page = fis.list_experiment_target_account_configurations(**kwargs)
        exp_seen.extend(c["accountId"] for c in page["targetAccountConfigurations"])
        next_token = page.get("nextToken")
        if not next_token:
            break

    assert sorted(exp_seen) == sorted(account_ids), (
        f"experiment-scoped list mismatch: {sorted(exp_seen)} != {sorted(account_ids)}"
    )


# ===== helpers =====
def _create_fis_role(ctx, iam) -> str:
    name = ctx.unique_name("sim2real-fis-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "fis.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
                description=ctx.unique_name("sim2real-data-fis-"),
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


def _start_experiment_retrying(ctx, fis, template_id: str, timeout_s: float = 30.0) -> str:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fis.start_experiment(
                clientToken=ctx.unique_name("sim2real-fis-start-"), experimentTemplateId=template_id
            )["experiment"]["id"]
        except ClientError as err:
            last_err = err
            time.sleep(2)
    raise last_err


def _stop_experiment_quiet(fis, experiment_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        fis.stop_experiment(id=experiment_id)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        # an experiment already in a final state rejects StopExperiment; it needs no stop
        status = fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"]
        if status not in ("stopping", "stopped", "completed", "failed", "cancelled"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
