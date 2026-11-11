"""reject-crawler-with-unassumable-role."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reject-crawler-with-unassumable-role"
GROUP = 'overly-permissive'
SERVICES = ['glue']

_ROLE_PROPAGATION_TIMEOUT_S = 180
_ROLE_PROPAGATION_POLL_S = 5
#: CreateCrawler's refusal of a role Glue cannot assume, also its answer while a new role propagates.
_UNASSUMABLE = "Service is unable to assume provided role. Please verify role's TrustPolicy"


def _create_bucket(ctx) -> str:
    """A real S3 bucket for the positive control: once the role is genuinely assumable,
    CreateCrawler goes on to validate the S3 target itself, and a fabricated bucket name
    404s there instead of at the AssumeRole probe this check exists to exercise."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-glue-crawler-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    return bucket


def _assumable_role(ctx) -> str:
    """An IAM role Glue can really assume, so the positive control below is real."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-glue-role-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "glue.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    managed = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    ctx.on_cleanup(lambda: _delete_role(iam, name, managed))
    iam.attach_role_policy(RoleName=name, PolicyArn=managed)
    return arn


def _delete_role(iam, name, managed) -> None:
    try:
        iam.detach_role_policy(RoleName=name, PolicyArn=managed)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=name)


def _error(fn):
    """Call fn() and return (code, message) of the refusal; an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _create_crawler_awaiting_propagation(glue, *, name, role, db_name, target_path):
    """CreateCrawler with a genuinely-assumable role can still race IAM propagation and be
    refused with the SAME InvalidInputException the unassumable-role case raises below, so the
    positive control needs its own bounded retry rather than a fixed sleep."""
    deadline = time.monotonic() + _ROLE_PROPAGATION_TIMEOUT_S
    while True:
        try:
            glue.create_crawler(
                Name=name,
                Role=role,
                DatabaseName=db_name,
                Targets={"S3Targets": [{"Path": target_path}]},
                Tags={"sim2real": CHECK},
            )
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message")
            propagating = (code, message) == ("InvalidInputException", _UNASSUMABLE)
            if not propagating or time.monotonic() >= deadline:
                raise AssertionError(
                    "positive control CreateCrawler with a real assumable role failed: "
                    f"{code}: {exc.response.get('Error', {}).get('Message')}"
                ) from exc
            time.sleep(_ROLE_PROPAGATION_POLL_S)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCrawler with a role Glue cannot assume raises InvalidInputException with the exact
    message and GetCrawler on that name raises EntityNotFoundException, while a crawler with an
    assumable role is READY.
    """
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    # Positive control: a role Glue can really assume is accepted.
    good_role = _assumable_role(ctx)
    good_bucket = _create_bucket(ctx)
    good_name = ctx.unique_name("sim2real-behav-crawler-ok-")
    good_target = f"s3://{good_bucket}/"
    _create_crawler_awaiting_propagation(
        glue, name=good_name, role=good_role, db_name=db_name, target_path=good_target
    )
    ctx.on_cleanup(lambda: glue.delete_crawler(Name=good_name))
    state = glue.get_crawler(Name=good_name)["Crawler"]["State"]
    assert state == "READY", f"positive control crawler was not created cleanly, state={state}"

    # Break exactly one thing: a role Glue was never granted permission to assume.
    name = ctx.unique_name("sim2real-behav-crawler-")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bogus_role = f"arn:aws:iam::{account}:role/{ctx.unique_name('sim2real-behav-unassumable-role-')}"
    target_path = f"s3://{ctx.unique_name('sim2real-behav-glue-behavioral-bucket-')}/data/"

    def _create_bogus():
        glue.create_crawler(
            Name=name,
            Role=bogus_role,
            DatabaseName=db_name,
            Targets={"S3Targets": [{"Path": target_path}]},
        )
        ctx.on_cleanup(lambda: glue.delete_crawler(Name=name))

    code, message = _error(_create_bogus)
    assert code == "InvalidInputException", f"expected InvalidInputException, got {code}"
    assert message == _UNASSUMABLE, message

    # And the crawler must not exist afterwards.
    get_code, get_message = _error(lambda: glue.get_crawler(Name=name))
    assert get_code == "EntityNotFoundException", (
        f"rejected crawler was still persisted (get_crawler -> {get_code})"
    )
    assert get_message == f"Crawler entry with name {name} does not exist", get_message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
