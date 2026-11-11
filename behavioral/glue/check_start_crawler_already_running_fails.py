"""start-crawler-already-running-fails."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-crawler-already-running-fails"
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
    """A Glue-assumable IAM role this check creates and tears down."""
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

def _refusal(call):
    """(code, message) of a call that MUST be refused; raises when the call succeeds."""
    try:
        call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to be refused but it SUCCEEDED")


def _poll(fn, pred, timeout_s, interval_s):
    deadline = time.time() + timeout_s
    val = fn()
    while not pred(val):
        if time.time() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _retry_call(fn, timeout_s=90.0, interval_s=2.0, retry_codes=("AccessDeniedException", "InvalidInputException")):
    """Bounded retry for the freshly-created role's IAM-to-Glue propagation window."""
    deadline = time.time() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in retry_codes and time.time() < deadline:
                time.sleep(interval_s)
                continue
            raise

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Calling start_crawler while the crawler is already RUNNING raises CrawlerRunningException."""
    glue = ctx.client("glue")
    role = _glue_role_arn(ctx)
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    crawler_name = ctx.unique_name("sim2real-behav-crawler-")
    _retry_call(
        lambda: glue.create_crawler(
            Name=crawler_name,
            Role=role,
            DatabaseName=db_name,
            Targets={"S3Targets": [{"Path": "s3://example-bucket/data/"}]},
            Tags={"sim2real": CHECK},
        )
    )
    ctx.on_cleanup(lambda: glue.delete_crawler(Name=crawler_name))

    _retry_call(lambda: glue.start_crawler(Name=crawler_name))
    try:
        # Wait until the crawler is unambiguously RUNNING so the rejection
        # contract is exercised deterministically rather than racing the run.
        state = _poll(
            lambda: glue.get_crawler(Name=crawler_name)["Crawler"]["State"],
            lambda state: state == "RUNNING",
            timeout_s=_budget_s(ctx, 120),
            interval_s=1,
        )
        if state != "RUNNING" and _budget_spent(ctx):
            raise TimeoutError(f"crawler {crawler_name} reaching RUNNING: the run budget ended first; not graded")
        assert state == "RUNNING", f"the crawler never reached RUNNING, last state {state}"
        code, message = _refusal(lambda: glue.start_crawler(Name=crawler_name))
        assert code == "CrawlerRunningException", (
            f"expected CrawlerRunningException for concurrent start, got {code}"
        )
        assert message == f"Crawler with name {crawler_name} has already started", message

        # StopCrawler is only legal from RUNNING; it moves the crawler to STOPPING, and the
        # crawler then settles back at READY. A crawl that finished on its own after the refused
        # start is refused with CrawlerNotRunningException instead.
        try:
            glue.stop_crawler(Name=crawler_name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "CrawlerNotRunningException":
                raise
        stopping = glue.get_crawler(Name=crawler_name)["Crawler"]["State"]
        assert stopping in ("STOPPING", "READY"), (
            f"StopCrawler must move the crawler out of RUNNING, got {stopping}"
        )
    finally:
        settled = _poll(
            lambda: glue.get_crawler(Name=crawler_name)["Crawler"]["State"],
            lambda state: state == "READY",
            timeout_s=_budget_s(ctx, 240),
            interval_s=1,
        )
    if settled != "READY" and _budget_spent(ctx):
        raise TimeoutError(f"crawler {crawler_name} settling at READY: the run budget ended first; not graded")
    assert settled == "READY", f"StopCrawler must return the crawler to READY, got {settled}"

    # Effect absent: the rejected concurrent start must not have launched a second crawl.
    crawls = glue.list_crawls(CrawlerName=crawler_name)["Crawls"]
    assert len(crawls) == 1, (
        f"expected exactly the one crawl that was actually run, got {len(crawls)}: {crawls}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
