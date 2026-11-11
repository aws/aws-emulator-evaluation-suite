"""create-crawler-no-targets-fails."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-crawler-no-targets-fails"
GROUP = 'overly-permissive'
SERVICES = ['glue']

def _delete_role(iam, name):
    try:
        for pol in iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", []):
            try:
                iam.detach_role_policy(RoleName=name, PolicyArn=pol["PolicyArn"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=name)


def _glue_role_arn(ctx):
    """Create a dedicated Glue-assumable IAM role for THIS check and return its ARN.

    Created and attached in-check; any failure raises rather than falling back to an
    existing account role or a synthesized (never-created) ARN, either of which would
    make a later InvalidInputException ambiguous between "no targets" and "bad role".
    """
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-glue-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "glue.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="SimParity behavioral fidelity check role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    iam.attach_role_policy(
        RoleName=name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
    )
    return resp["Role"]["Arn"]


def _create_crawler_when_role_ready(glue, *, timeout_s=90, interval_s=5, **kwargs):
    """Retry CreateCrawler while Glue's own AssumeRole propagation probe is still
    catching up to the just-attached policy.

    Targets is valid on every attempt here, so an InvalidInputException in this loop
    can only be that transient role probe, never the no-targets rejection under test --
    bound it with a deadline instead of a fixed sleep, and raise (never swallow) once
    the deadline passes.
    """
    deadline = time.time() + timeout_s
    while True:
        try:
            return glue.create_crawler(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidInputException":
                raise
            if time.time() >= deadline:
                raise
            time.sleep(interval_s)

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """create_crawler with an empty Targets map must raise InvalidInputException,
    while the identical account/role/database combination with a real target succeeds."""
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    role_arn = _glue_role_arn(ctx)

    # Positive control: the same role and database create a crawler fine when the
    # Targets map is non-empty, so a later rejection is provably about the empty
    # Targets and not a broken role, database or account.
    control_name = ctx.unique_name("sim2real-behav-crawler-ok-")
    _create_crawler_when_role_ready(
        glue,
        Name=control_name,
        Role=role_arn,
        DatabaseName=db_name,
        Targets={"S3Targets": [{"Path": "s3://example-bucket/data/"}]},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_crawler(Name=control_name))
    control_state = glue.get_crawler(Name=control_name)["Crawler"]["State"]
    assert control_state == "READY", (
        f"positive control: expected a freshly created crawler to read back READY, got {control_state}"
    )

    crawler_name = ctx.unique_name("sim2real-behav-crawler-")
    try:
        glue.create_crawler(
            Name=crawler_name,
            Role=role_arn,
            DatabaseName=db_name,
            Targets={},
            Tags={"sim2real": CHECK},
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
    else:
        ctx.on_cleanup(lambda: glue.delete_crawler(Name=crawler_name))
        raise AssertionError("expected CreateCrawler with no targets to be rejected, but it succeeded")
    assert code == "InvalidInputException", (
        f"expected InvalidInputException for a crawler with no targets, got {code}"
    )
    assert message == "Targets are not defined", f"unexpected CreateCrawler message: {message!r}"

    # And the rejected crawler must not have been persisted -- an independent read at
    # the same operation the positive control just proved works.
    try:
        glue.get_crawler(Name=crawler_name)
    except ClientError as exc:
        get_code = exc.response["Error"]["Code"]
        get_message = exc.response["Error"].get("Message")
    else:
        raise AssertionError(f"rejected crawler {crawler_name} was still persisted")
    assert get_code == "EntityNotFoundException", (
        f"rejected crawler was still persisted (get_crawler -> {get_code})"
    )
    assert get_message == f"Crawler entry with name {crawler_name} does not exist", (
        f"unexpected GetCrawler message: {get_message!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
