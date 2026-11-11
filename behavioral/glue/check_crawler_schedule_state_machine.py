"""crawler-schedule-state-machine."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "crawler-schedule-state-machine"
GROUP = 'crawler'
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
    """Create a dedicated Glue-assumable IAM role for this check and return its ARN; any
    failure raises rather than falling back to a role the check did not create."""
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

def _retry_iam_propagation(fn, *, timeout_s=60.0, interval_s=5.0):
    """Newly-created IAM roles/policies take time to propagate; Glue's AssumeRole
    probe fails with AccessDeniedException/InvalidInputException if we race ahead.
    Retry on that specific error, bounded by a deadline, instead of a blind sleep."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "InvalidInputException") and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _poll(fn, pred, timeout_s, interval_s):
    deadline = time.time() + timeout_s
    val = fn()
    while not pred(val):
        if time.time() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val

def _schedule_state(glue, crawler_name):
    return glue.get_crawler(Name=crawler_name)["Crawler"]["Schedule"]["State"]

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """update_crawler_schedule moves Schedule.State NOT_SCHEDULED -> SCHEDULED -> NOT_SCHEDULED."""
    glue = ctx.client("glue")
    role = _glue_role_arn(ctx)
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    crawler_name = ctx.unique_name("sim2real-behav-crawler-")
    _retry_iam_propagation(
        lambda: glue.create_crawler(
            Name=crawler_name,
            Role=role,
            DatabaseName=db_name,
            Description="v1",
            Targets={"S3Targets": [{"Path": "s3://example-bucket/data-v1/"}]},
        )
    )
    ctx.on_cleanup(lambda: glue.delete_crawler(Name=crawler_name))

    glue.update_crawler(
        Name=crawler_name,
        Role=role,
        Description="v2",
        Targets={"S3Targets": [{"Path": "s3://example-bucket/data-v2/"}]},
    )
    crawler = glue.get_crawler(Name=crawler_name)["Crawler"]
    assert crawler["Description"] == "v2", f"UpdateCrawler did not persist Description: {crawler}"
    paths = [t["Path"] for t in crawler["Targets"]["S3Targets"]]
    assert paths == ["s3://example-bucket/data-v2/"], f"targets not updated: {paths}"

    glue.update_crawler_schedule(CrawlerName=crawler_name, Schedule="cron(0 1 * * ? *)")
    scheduled = _poll(
        lambda: _schedule_state(glue, crawler_name),
        lambda s: s == "SCHEDULED",
        timeout_s=60,
        interval_s=2,
    )
    assert scheduled == "SCHEDULED", f"crawler schedule did not become SCHEDULED: {scheduled}"

    glue.stop_crawler_schedule(CrawlerName=crawler_name)
    not_scheduled = _poll(
        lambda: _schedule_state(glue, crawler_name),
        lambda s: s == "NOT_SCHEDULED",
        timeout_s=60,
        interval_s=2,
    )
    assert not_scheduled == "NOT_SCHEDULED", (
        f"crawler schedule did not become NOT_SCHEDULED: {not_scheduled}"
    )

    batch = glue.batch_get_crawlers(CrawlerNames=[crawler_name, "does-not-exist-crawler"])
    found = [c["Name"] for c in batch["Crawlers"]]
    assert found == [crawler_name], f"BatchGetCrawlers should return only {crawler_name!r}, got {found!r}"
    assert batch["CrawlersNotFound"] == ["does-not-exist-crawler"], (
        f"unknown crawler must be reported in CrawlersNotFound: {batch['CrawlersNotFound']}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
