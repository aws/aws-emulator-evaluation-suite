"""apply-archive-rule-archives-real-finding-end-to-end."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "apply-archive-rule-archives-real-finding-end-to-end"
GROUP = "cross-service"
SERVICES = ["accessanalyzer"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "cap:c7", "concern:e2e", "plane:control", "resource:account-singleton:accessanalyzer-account-analyzer")
def run(ctx) -> None:
    """A public SQS queue policy produces an ACTIVE ExternalAccess finding once the analyzer scans
    the queue, and ApplyArchiveRule then flips that existing finding to ARCHIVED."""
    aa = ctx.client("accessanalyzer")
    sqs = ctx.client("sqs")

    analyzer_name = ctx.unique_name("sim2real-aa-e2e-")
    analyzer_arn = aa.create_analyzer(analyzerName=analyzer_name, type="ACCOUNT")["arn"]
    ctx.on_cleanup(lambda: aa.delete_analyzer(analyzerName=analyzer_name))
    _poll_analyzer_status(ctx, analyzer_name)

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-aa-e2e-queue-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "PublicSend",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "SQS:SendMessage",
            "Resource": queue_arn,
        }],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})

    aa.start_resource_scan(analyzerArn=analyzer_arn, resourceArn=queue_arn)

    finding = _poll_for_finding(ctx, analyzer_arn, queue_arn)
    assert finding is not None, "no ExternalAccess finding materialized for the shared SQS queue"
    assert finding["status"] == "ACTIVE", finding
    assert finding["resourceType"] == "AWS::SQS::Queue", finding

    rule_name = ctx.unique_name("sim2real-aa-e2e-rule-")
    aa.create_archive_rule(
        analyzerName=analyzer_name,
        ruleName=rule_name,
        filter={"resource": {"eq": [queue_arn]}},
    )
    aa.apply_archive_rule(analyzerArn=analyzer_arn, ruleName=rule_name)

    archived_status = _poll_finding_status(ctx, analyzer_arn, finding["id"])
    assert archived_status == "ARCHIVED", f"finding never transitioned to ARCHIVED, last status={archived_status}"


def _poll_analyzer_status(ctx, name: str, timeout_s: float = 90.0, interval_s: float = 3.0) -> str:
    aa = ctx.client("accessanalyzer")
    deadline = time.monotonic() + timeout_s
    status = "CREATING"
    while time.monotonic() < deadline:
        status = aa.get_analyzer(analyzerName=name)["analyzer"]["status"]
        if status != "CREATING":
            return status
        time.sleep(interval_s)
    return status


def _poll_for_finding(ctx, analyzer_arn: str, resource_arn: str, timeout_s: float = 600.0, interval_s: float = 15.0):
    aa = ctx.client("accessanalyzer")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        findings = aa.list_findings(analyzerArn=analyzer_arn, filter={"resource": {"eq": [resource_arn]}})["findings"]
        active = [f for f in findings if f["status"] == "ACTIVE"]
        if active:
            return active[0]
        time.sleep(interval_s)
    return None


def _poll_finding_status(ctx, analyzer_arn: str, finding_id: str, timeout_s: float = 300.0, interval_s: float = 10.0) -> str:
    aa = ctx.client("accessanalyzer")
    deadline = time.monotonic() + timeout_s
    status = "ACTIVE"
    while time.monotonic() < deadline:
        status = aa.get_finding(analyzerArn=analyzer_arn, id=finding_id)["finding"]["status"]
        if status == "ARCHIVED":
            return status
        time.sleep(interval_s)
    return status


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
