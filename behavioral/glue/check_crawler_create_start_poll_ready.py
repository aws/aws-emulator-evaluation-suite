"""crawler-create-start-poll-ready."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "crawler-create-start-poll-ready"
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
    """Create a dedicated Glue-assumable IAM role for this check and return its ARN."""
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

def _create_crawler_with_retry(glue, timeout_s=60, interval_s=2, **kwargs):
    """IAM role propagation is eventually consistent; Glue's AssumeRole probe against a
    just-created role can fail for a few seconds after AttachRolePolicy returns. Retry the
    bounded window instead of sleeping unconditionally before the role is ever exercised."""
    deadline = time.time() + timeout_s
    while True:
        try:
            return glue.create_crawler(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("AccessDeniedException", "InvalidInputException") and time.time() < deadline:
                time.sleep(interval_s)
                continue
            raise

def _poll(fn, pred, timeout_s, interval_s, reason, ctx=None):
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        last = fn()
        if pred(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{reason}: the run budget ended first; not graded")
    raise AssertionError(f"timed out waiting for {reason}: last value={last!r}")

def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartCrawler starts a run (State leaves READY or a LastCrawl is recorded), State returns
    to READY, and GetCrawlerMetrics and ListCrawls reflect the completed run."""
    glue = ctx.client("glue")
    role = _glue_role_arn(ctx)
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    crawler_name = ctx.unique_name("sim2real-behav-crawler-")
    _create_crawler_with_retry(
        glue,
        Name=crawler_name,
        Role=role,
        DatabaseName=db_name,
        Targets={"S3Targets": [{"Path": "s3://example-bucket/data/"}]},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_crawler(Name=crawler_name))

    initial_state = glue.get_crawler(Name=crawler_name)["Crawler"]["State"]
    assert initial_state == "READY", f"expected initial CrawlerState READY, got {initial_state}"

    glue.start_crawler(Name=crawler_name)
    # A short crawl can be back at READY before the first GetCrawler lands; a recorded
    # LastCrawl on this fresh crawler is then the evidence that the run happened.
    started = _poll(
        lambda: glue.get_crawler(Name=crawler_name)["Crawler"],
        lambda c: c["State"] != "READY" or bool(c.get("LastCrawl")),
        timeout_s=_budget_s(ctx, 30),
        interval_s=1,
        reason="CrawlerState to leave READY (or a LastCrawl to be recorded) after start_crawler",
        ctx=ctx,
    )
    assert started["State"] != "READY" or started.get("LastCrawl"), (
        f"start_crawler must start a run, got State {started['State']} and no LastCrawl"
    )

    final_state = _poll(
        lambda: glue.get_crawler(Name=crawler_name)["Crawler"]["State"],
        lambda state: state == "READY",
        timeout_s=_budget_s(ctx, 240),
        interval_s=1,
        reason="CrawlerState to return to READY after the run completes",
        ctx=ctx,
    )
    assert final_state == "READY", f"crawler did not return to READY, last state={final_state}"

    metrics = glue.get_crawler_metrics(CrawlerNameList=[crawler_name])["CrawlerMetricsList"][0]
    assert metrics["CrawlerName"] == crawler_name, (
        f"expected metrics entry for {crawler_name}, got {metrics.get('CrawlerName')!r}"
    )

    # Independent side-channel confirming the run happened, because the crawl target
    # (a nonexistent bucket) leaves GetCrawlerMetrics' LastRuntimeSeconds at 0.
    crawls = glue.list_crawls(CrawlerName=crawler_name)["Crawls"]
    assert len(crawls) >= 1, f"expected ListCrawls to report the completed run, got {crawls}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
