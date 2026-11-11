"""reject-get-nonexistent-crawler."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reject-get-nonexistent-crawler"
GROUP = 'overly-permissive'
SERVICES = ['glue']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetCrawler on a never-created name raises EntityNotFoundException ("Crawler entry with name
    <name> does not exist"), while GetCrawler on a real crawler returns its Name.
    """
    glue = ctx.client("glue")

    role_arn = _glue_role_arn(ctx)
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    real_name = ctx.unique_name("sim2real-behav-crawler-")
    _create_crawler_with_role_propagation_retry(
        glue,
        Name=real_name,
        Role=role_arn,
        DatabaseName=db_name,
        # CreateCrawler HeadBucket-validates the S3 target and 404s on a bucket that plainly does
        # not exist; "example-bucket" is the placeholder used elsewhere in this suite precisely
        # because it clears that check.
        Targets={"S3Targets": [{"Path": "s3://example-bucket/data/"}]},
    )
    ctx.on_cleanup(lambda: glue.delete_crawler(Name=real_name))

    # Positive control: the identical GetCrawler call succeeds against a real crawler.
    described = glue.get_crawler(Name=real_name)["Crawler"]
    assert described["Name"] == real_name, f"expected Name {real_name}, got {described.get('Name')}"

    missing_name = ctx.unique_name("sim2real-behav-no-such-crawler-")
    code, message = _error(lambda: glue.get_crawler(Name=missing_name))
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}"
    assert message == f"Crawler entry with name {missing_name} does not exist", message

def _error(fn):
    """Call fn() and return (code, message) of the refusal; an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


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

    CreateCrawler performs a real AssumeRole probe, so the positive control needs a role Glue can
    actually assume, not a synthesized ARN.
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
    )
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    iam.attach_role_policy(
        RoleName=name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
    )
    return resp["Role"]["Arn"]


def _create_crawler_with_role_propagation_retry(glue, **kwargs):
    """CreateCrawler probes AssumeRole on the freshly created role; retry the identical call,
    bounded, while that IAM trust grant propagates -- never an unconditional sleep."""
    deadline = time.monotonic() + 60.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            glue.create_crawler(**kwargs)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("InvalidInputException", "AccessDeniedException"):
                last_err = exc
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"could not create crawler after role propagation wait: {last_err}")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
