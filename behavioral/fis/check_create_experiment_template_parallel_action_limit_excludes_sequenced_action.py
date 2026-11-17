"""create-experiment-template-parallel-action-limit-excludes-sequenced-action."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-experiment-template-parallel-action-limit-excludes-sequenced-action"
GROUP = "template"
SERVICES = ["fis"]

_WAIT_ACTION_ID = "aws:fis:wait"
_QUOTA_ERR = (
    "ServiceQuotaExceededException",
    "The number of parallel actions cannot exceed 10",
)
_TRANSIENT_ROLE_PROPAGATION_CODES = ("ResourceNotFoundException", "AccessDeniedException")


def _delete_role(iam, role_name):
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _experiment_role_arn(ctx):
    """Create an IAM role trusted by fis.amazonaws.com; return its ARN. Tracked for teardown."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-fis-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "fis.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="fis-inline",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        ),
    )
    return resp["Role"]["Arn"]


def _create_with_retry(fis, kwargs, timeout_s: float = 45.0):
    """CreateExperimentTemplate, retrying only the transient rejection a just-created IAM
    role gets before fis.amazonaws.com can assume it. Raises on any other ClientError."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fis.create_experiment_template(**kwargs)["experimentTemplate"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in _TRANSIENT_ROLE_PROPAGATION_CODES and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success fails too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        got = (err.get("Code"), err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _delete_template_quiet(fis, template_id):
    try:
        fis.delete_experiment_template(id=template_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _templates_tagged(fis, tag_key, tag_value):
    pages = fis.get_paginator("list_experiment_templates").paginate(maxResults=100)
    return [
        t
        for page in pages
        for t in page["experimentTemplates"]
        if t.get("tags", {}).get(tag_key) == tag_value
    ]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateExperimentTemplate with 11 unsequenced aws:fis:wait actions is refused with
    ServiceQuotaExceededException and creates nothing, while 10 actions succeed and read
    back intact, and 11 actions where the 11th starts after the first are also accepted.
    """
    fis = ctx.client("fis")
    role = _experiment_role_arn(ctx)
    probe_token = ctx.unique_name("sim2real-behav-quota-probe-")

    over_names = [f"wait{i}" for i in range(11)]
    over_actions = {
        name: {"actionId": _WAIT_ACTION_ID, "parameters": {"duration": "PT1M"}}
        for name in over_names
    }
    expect_error(
        lambda: _create_with_retry(
            fis,
            dict(
                clientToken=ctx.unique_name("sim2real-behav-quota-over-"),
                description="FIS parallel action quota",
                roleArn=role,
                stopConditions=[{"source": "none"}],
                targets={},
                actions=over_actions,
                tags={"sim2real:quota-probe": probe_token},
            ),
        ),
        *_QUOTA_ERR,
    )
    leftover = _templates_tagged(fis, "sim2real:quota-probe", probe_token)
    assert leftover == [], f"refused create left a template behind: {leftover}"

    # Positive control: exactly 10 parallel actions is accepted, and every action name
    # and action id comes back unchanged.
    at_limit_names = [f"wait{i}" for i in range(10)]
    at_limit_actions = {
        name: {"actionId": _WAIT_ACTION_ID, "parameters": {"duration": "PT1M"}}
        for name in at_limit_names
    }
    try:
        at_limit_template = _create_with_retry(
            fis,
            dict(
                clientToken=ctx.unique_name("sim2real-behav-atlimit-"),
                description="FIS parallel action quota at limit",
                roleArn=role,
                stopConditions=[{"source": "none"}],
                targets={},
                actions=at_limit_actions,
            ),
        )
    except ClientError as exc:
        raise AssertionError(f"expected success at the 10-action limit, got {exc.response['Error']}") from exc
    ctx.on_cleanup(lambda: _delete_template_quiet(fis, at_limit_template["id"]))
    at_limit_read_back = fis.get_experiment_template(id=at_limit_template["id"])["experimentTemplate"]
    assert set(at_limit_read_back["actions"]) == set(at_limit_names), (
        f"expected action names {sorted(at_limit_names)}, got {sorted(at_limit_read_back['actions'])}"
    )
    for name in at_limit_names:
        assert at_limit_read_back["actions"][name]["actionId"] == _WAIT_ACTION_ID, (
            name,
            at_limit_read_back["actions"][name],
        )

    # 11 actions where the 11th starts after the first: accepted, because a sequenced
    # action does not count toward the parallel-action limit.
    sequenced_names = [f"dep{i}" for i in range(10)] + ["depLast"]
    sequenced_actions = {
        name: {"actionId": _WAIT_ACTION_ID, "parameters": {"duration": "PT1M"}}
        for name in sequenced_names
    }
    sequenced_actions["depLast"]["startAfter"] = [sequenced_names[0]]
    try:
        sequenced_template = _create_with_retry(
            fis,
            dict(
                clientToken=ctx.unique_name("sim2real-behav-sequenced-"),
                description="FIS parallel action quota with one sequenced action",
                roleArn=role,
                stopConditions=[{"source": "none"}],
                targets={},
                actions=sequenced_actions,
            ),
        )
    except ClientError as exc:
        raise AssertionError(
            f"expected 11 actions with one sequenced to be accepted, got {exc.response['Error']}"
        ) from exc
    ctx.on_cleanup(lambda: _delete_template_quiet(fis, sequenced_template["id"]))
    sequenced_read_back = fis.get_experiment_template(id=sequenced_template["id"])["experimentTemplate"]
    assert set(sequenced_read_back["actions"]) == set(sequenced_names), (
        f"expected action names {sorted(sequenced_names)}, got {sorted(sequenced_read_back['actions'])}"
    )
    assert sequenced_read_back["actions"]["depLast"].get("startAfter") == [sequenced_names[0]], (
        sequenced_read_back["actions"]["depLast"].get("startAfter")
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
