"""cli-redshift-data-execute-statement-eventbridge-sqs-notify."""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-redshift-data-execute-statement-eventbridge-sqs-notify"
GROUP = "cli_workflows"
SERVICES = ["redshift", "sqs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """`aws redshift-data execute-statement --with-event` emits a "Redshift Data Statement Status
    Change" event that a rule routes to SQS, with statementId/state/resources matching the run."""
    require_tools("aws")

    cluster = _create_redshift_cluster(ctx)
    rule = _create_redshift_event_rule(ctx, "notify")
    queue = _create_queue(ctx, "notify")
    _set_queue_policy_for_rule(ctx, queue, rule["arn"])
    _put_target(ctx, rule["name"], "sqs-target", queue["arn"])

    statement_id = _execute_statement(ctx, cluster, "SELECT 1")
    status = _wait_statement_status(ctx, statement_id)
    assert status == "FINISHED", f"expected statement to FINISH, got {status}"

    event = _poll_for_statement_message(ctx, queue["url"], statement_id, timeout_s=180.0)
    assert event is not None, "no EventBridge notification for the statement reached SQS"
    assert event["source"] == "aws.redshift-data", f"expected source aws.redshift-data, got {event['source']!r}"
    assert event["detail-type"] == "Redshift Data Statement Status Change", (
        f"expected detail-type 'Redshift Data Statement Status Change', got {event['detail-type']!r}"
    )
    detail = event["detail"]
    assert detail["statementId"] == statement_id, f"expected statementId {statement_id}, got {detail['statementId']!r}"
    assert detail["state"] == "FINISHED", f"expected state FINISHED, got {detail['state']!r}"
    cluster_fragment = f"cluster:{cluster['cluster_id']}"
    resources = event.get("resources", [])
    assert any(cluster_fragment in r for r in resources), (
        f"expected a resource containing {cluster_fragment!r}, got {resources!r}"
    )


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_script(ctx, script: str, *, timeout_s=120.0, check=True, env_extra=None):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
        f.write("#!/bin/bash\nset -euo pipefail\n")
        f.write(script)
        script_path = f.name
    try:
        os.chmod(script_path, 0o755)
        return _run_shell(ctx, ["bash", script_path], timeout_s=timeout_s, check=check, env_extra=env_extra)
    finally:
        os.unlink(script_path)


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(ctx, ["aws", "--output", "json", *args], env_extra={"AWS_PAGER": ""}, timeout_s=timeout_s, check=check)
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _create_redshift_cluster(ctx) -> dict:
    redshift = ctx.client("redshift")
    cluster_id = ctx.unique_name("sim2real-rsq-")
    master_user = "sim2realuser"
    master_password = "Sim2Real1" + secrets.token_hex(4).capitalize() + "!"
    subnet_group = _network_redshift_subnet_group(ctx, redshift)
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType="ra3.xlplus",
        ClusterType="single-node",
        MasterUsername=master_user,
        MasterUserPassword=master_password,
        DBName="dev",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        ClusterSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: redshift.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True))
    _wait_cluster_available(ctx, cluster_id)
    return {"cluster_id": cluster_id, "master_user": master_user, "database": "dev"}


def _wait_cluster_available(ctx, cluster_id, timeout_s=900.0, interval_s=15.0) -> None:
    redshift = ctx.client("redshift")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        clusters = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"]
        status = clusters[0]["ClusterStatus"] if clusters else None
        if status == "available":
            return
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_id} never became available, last status={status}")


def _create_queue(ctx, suffix: str) -> dict:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name(f"sim2real-rsq-{suffix}-"),
        tags={"sim2real-check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _set_queue_policy_for_rule(ctx, queue: dict, rule_arn: str) -> None:
    sqs = ctx.client("sqs")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowEventBridge",
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue["arn"],
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)})


def _create_redshift_event_rule(ctx, suffix: str) -> dict:
    events = ctx.client("events")
    name = ctx.unique_name(f"sim2real-rsrule-{suffix}-")
    pattern = {"source": ["aws.redshift-data"], "detail-type": ["Redshift Data Statement Status Change"]}
    resp = events.put_rule(
        Name=name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=name))
    return {"name": name, "arn": resp["RuleArn"]}


def _put_target(ctx, rule_name: str, target_id: str, target_arn: str) -> dict:
    events = ctx.client("events")
    resp = events.put_targets(Rule=rule_name, Targets=[{"Id": target_id, "Arn": target_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=[target_id]))
    return resp


def _execute_statement(ctx, cluster: dict, sql: str, statement_name: str | None = None) -> str:
    args = [
        "redshift-data", "execute-statement",
        "--cluster-identifier", cluster["cluster_id"],
        "--database", cluster["database"],
        "--db-user", cluster["master_user"],
        "--sql", sql,
        "--with-event",
    ]
    if statement_name:
        args += ["--statement-name", statement_name]
    result = _run_aws(ctx, *args)
    return result["Id"]


def _wait_statement_status(ctx, statement_id: str, timeout_s=180.0, interval_s=5.0) -> str:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        desc = _run_aws(ctx, "redshift-data", "describe-statement", "--id", statement_id)
        last_status = desc.get("Status")
        if last_status in ("FINISHED", "FAILED", "ABORTED"):
            return last_status
        time.sleep(interval_s)
    raise AssertionError(f"statement {statement_id} never reached a terminal state (last={last_status})")


def _poll_for_statement_message(ctx, queue_url: str, statement_id: str, timeout_s=180.0, interval_s=5.0):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = None
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if body and body.get("detail", {}).get("statementId") == statement_id:
                return body
        time.sleep(interval_s)
    return None


def _network_redshift_subnet_group(ctx, client) -> str:
    """A Redshift cluster subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-rsg-")
    client.create_cluster_subnet_group(
        ClusterSubnetGroupName=name,
        Description="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_cluster_subnet_group(ClusterSubnetGroupName=name),
            ("InvalidClusterSubnetGroupStateFault", "ClusterSubnetGroupInUse"),
            ("ClusterSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
