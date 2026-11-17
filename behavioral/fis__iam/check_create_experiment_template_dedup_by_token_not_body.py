"""create-experiment-template-dedup-by-token-not-body."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-experiment-template-dedup-by-token-not-body"
GROUP = "template"
SERVICES = ["fis", "iam"]

_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "fis.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def _delete_role(iam, role_name):
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_role(ctx):
    """An IAM role trusted by fis.amazonaws.com with full access; returns its ARN."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-fis-token-role-")
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_TRUST_POLICY),
        Path="/sim2real/",
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


def _delete_template_quiet(fis, template_id):
    try:
        fis.delete_experiment_template(id=template_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_template(ctx, fis, role_arn, client_token, run_tag, *, tries=10, delay_s=3.0):
    """CreateExperimentTemplate with a fixed, targetless, wait-only body under client_token.
    Retries past IAM role propagation lag. Tracked for cleanup."""
    kwargs = dict(
        clientToken=client_token,
        description="sim2real idempotency probe template",
        roleArn=role_arn,
        stopConditions=[{"source": "none"}],
        targets={},
        actions={"wait": {"actionId": "aws:fis:wait", "parameters": {"duration": "PT1M"}}},
        tags={"sim2real-run": run_tag},
    )
    last_exc = None
    for _ in range(tries):
        try:
            template = fis.create_experiment_template(**kwargs)["experimentTemplate"]
            ctx.on_cleanup(lambda t=template: _delete_template_quiet(fis, t["id"]))
            return template
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = str(exc)
            if code == "ResourceNotFoundException" or (
                code == "ValidationException" and "assume role" in msg.lower()
            ):
                last_exc = exc
                time.sleep(delay_s)
                continue
            raise
    raise last_exc


def _list_by_run_tag(fis, run_tag):
    pages = fis.get_paginator("list_experiment_templates").paginate()
    return [
        t
        for page in pages
        for t in page["experimentTemplates"]
        if t.get("tags", {}).get("sim2real-run") == run_tag
    ]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateExperimentTemplate dedups on clientToken: a repeated call with the same token and
    body returns the same id and creationTime, and a different token for that same body
    creates a second template with a different id."""
    fis = ctx.client("fis")
    role_arn = _create_role(ctx)
    run_tag = ctx.unique_name("sim2real-idem-run-")
    token = ctx.unique_name("sim2real-idem-token-")

    first = _create_template(ctx, fis, role_arn, token, run_tag)
    second = _create_template(ctx, fis, role_arn, token, run_tag)
    assert second["id"] == first["id"], f"{second['id']!r} != {first['id']!r}"
    assert second["creationTime"] == first["creationTime"], (
        f"{second['creationTime']!r} != {first['creationTime']!r}"
    )

    matches = _list_by_run_tag(fis, run_tag)
    assert [t["id"] for t in matches] == [first["id"]], matches

    other_token = ctx.unique_name("sim2real-idem-token2-")
    third = _create_template(ctx, fis, role_arn, other_token, run_tag)
    assert third["id"] != first["id"], f"a different token produced the same id {third['id']!r}"

    matches = _list_by_run_tag(fis, run_tag)
    assert {t["id"] for t in matches} == {first["id"], third["id"]}, matches


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
