"""crawler-tags-round-trip-then-not-found-after-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "crawler-tags-round-trip-then-not-found-after-delete"
GROUP = "tagging"
SERVICES = ["glue", "iam", "s3"]


def _expect_error(fn, expected_code: str, expected_message: str) -> None:
    """Call ``fn()``; it must raise exactly ``(expected_code, expected_message)``."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got = (err.get("Code"), err.get("Message"))
        assert got == (expected_code, expected_message), (
            f"expected {(expected_code, expected_message)!r}, got {got!r}"
        )
        return
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_to_client_error(fn, *, budget_s: float = 30.0, poll_s: float = 2.0) -> None:
    """Poll ``fn`` until it raises a ``ClientError``, never grading the transient success."""
    deadline = time.monotonic() + budget_s
    last = None
    while True:
        try:
            last = fn()
        except ClientError:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"still answering after {budget_s}s instead of a refusal: {last!r}")
        time.sleep(poll_s)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; the resource's own
    not-found codes mean it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-glue-tags-").replace("_", "-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    return bucket


def _create_glue_role(ctx) -> str:
    """A dedicated IAM role trusting glue.amazonaws.com, carrying only the AWS-managed
    Glue service role policy; no S3 access, since the crawler is never started."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-glue-tags-role-")
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
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(
        _teardown(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn), "NoSuchEntity")
    )
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_crawler_with_role_propagation_retry(glue, **kwargs) -> None:
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTags on a crawler's ARN returns exactly its CreateCrawler Tags, then exactly what
    TagResource and UntagResource leave; once the crawler is deleted, GetTags on that ARN
    raises EntityNotFoundException, while a sibling crawler's tags stay readable.
    """
    glue = ctx.client("glue")
    bucket = _create_bucket(ctx)
    role_arn = _create_glue_role(ctx)
    db_name = ctx.unique_name("sim2real-behav-glue-tags-db-")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    def _crawler_arn(crawler_name: str) -> str:
        return f"arn:aws:glue:{ctx.region}:{ctx.account}:crawler/{crawler_name}"

    name = ctx.unique_name("sim2real-behav-glue-tags-crawler-")
    _create_crawler_with_role_propagation_retry(
        glue,
        Name=name,
        Role=role_arn,
        DatabaseName=db_name,
        Targets={"S3Targets": [{"Path": f"s3://{bucket}/"}]},
        Tags={"k1": "v1"},
    )
    deleted = {"value": False}

    def _cleanup_crawler() -> None:
        if not deleted["value"]:
            try:
                glue.delete_crawler(Name=name)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "EntityNotFoundException":
                    raise

    ctx.on_cleanup(_cleanup_crawler)
    arn = _crawler_arn(name)

    got = glue.get_tags(ResourceArn=arn)["Tags"]
    assert got == {"k1": "v1"}, f"expected the crawler's Tags right back, got {got!r}"

    glue.tag_resource(ResourceArn=arn, TagsToAdd={"k2": "v2"})
    got = glue.get_tags(ResourceArn=arn)["Tags"]
    assert got == {"k1": "v1", "k2": "v2"}, f"expected TagResource to add k2, got {got!r}"

    glue.untag_resource(ResourceArn=arn, TagsToRemove=["k1"])
    got = glue.get_tags(ResourceArn=arn)["Tags"]
    assert got == {"k2": "v2"}, f"expected UntagResource to remove k1 only, got {got!r}"

    control_name = ctx.unique_name("sim2real-behav-glue-tags-crawler-ctl-")
    _create_crawler_with_role_propagation_retry(
        glue,
        Name=control_name,
        Role=role_arn,
        DatabaseName=db_name,
        Targets={"S3Targets": [{"Path": f"s3://{bucket}/"}]},
        Tags={"k3": "v3"},
    )
    ctx.on_cleanup(lambda: glue.delete_crawler(Name=control_name))
    control_arn = _crawler_arn(control_name)
    got = glue.get_tags(ResourceArn=control_arn)["Tags"]
    assert got == {"k3": "v3"}, f"expected the control crawler's own Tags, got {got!r}"

    _NOT_FOUND = ("EntityNotFoundException", f"Crawler entry with name {name} does not exist")
    glue.delete_crawler(Name=name)
    deleted["value"] = True

    _poll_to_client_error(lambda: glue.get_tags(ResourceArn=arn))
    _expect_error(lambda: glue.get_tags(ResourceArn=arn), *_NOT_FOUND)

    # Positive control: deleting one crawler leaves a sibling crawler's tags readable.
    got = glue.get_tags(ResourceArn=control_arn)["Tags"]
    assert got == {"k3": "v3"}, f"expected the sibling crawler's Tags to survive, got {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
