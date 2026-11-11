"""repository-trigger-invokes-lambda-with-a-payload-naming-the-ref-update."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "repository-trigger-invokes-lambda-with-a-payload-naming-the-ref-update"
GROUP = "data-plane"
SERVICES = ["codecommit", "lambda", "logs"]

_ROLE_TIMEOUT_S = 90.0
_LOG_TIMEOUT_S = 150.0
#: The handler prints this prefix so a log scan can find the payload without parsing Lambda's
#: own START/END/REPORT lines.
_MARKER = "SIM2REAL-CC-TRIGGER "


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A CodeCommit trigger aimed at a Lambda function invokes it on a real ref update with a
    payload naming refs/heads/main and the exact commit id, as read from the function's own logs,
    and a commit on an unlisted branch never invokes it.

    Reference: https://docs.aws.amazon.com/codecommit/latest/userguide/how-to-notify-lambda.html
    """
    cc = ctx.client("codecommit")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    identity = sts.get_caller_identity()
    account = identity["Account"]
    partition = identity["Arn"].split(":")[1]

    # ---- The consumer: a function that prints whatever it is handed. ----
    role_name = ctx.unique_name("sim2real-behav-cclam-r-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=[{"Key": "sim2real", "Value": "cclam"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_execution = (
        f"arn:{partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    )
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_execution)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_execution)
    )

    fn_name = ctx.unique_name("sim2real-behav-cclam-f-")
    log_group = f"/aws/lambda/{fn_name}"
    fn_arn = _create_function(
        ctx, lam, fn_name=fn_name, role_arn=role_arn, timeout_s=_ROLE_TIMEOUT_S
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    # Lambda creates the group on first invocation; deleting it is this check's responsibility.
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    repo_name = ctx.unique_name("sim2real-behav-cclam-repo-")
    repo_arn = cc.create_repository(
        repositoryName=repo_name, tags={"sim2real": "cclam"}
    )["repositoryMetadata"]["Arn"]
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    statement_id = "sim2real-codecommit-invoke"
    lam.add_permission(
        FunctionName=fn_name,
        StatementId=statement_id,
        Action="lambda:InvokeFunction",
        Principal="codecommit.amazonaws.com",
        SourceArn=repo_arn,
        SourceAccount=account,
    )
    ctx.on_cleanup(
        lambda: lam.remove_permission(FunctionName=fn_name, StatementId=statement_id)
    )

    seed = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        filePath="seed.txt",
        fileContent=b"seed\n",
        commitMessage="seed",
    )["commitId"]
    cc.create_branch(repositoryName=repo_name, branchName="unlisted", commitId=seed)

    trigger_name = ctx.unique_name("sim2real-behav-cclam-t-")
    trigger = {
        "name": trigger_name,
        "destinationArn": fn_arn,
        "branches": ["main"],
        "events": ["updateReference"],
    }
    config_id = cc.put_repository_triggers(
        repositoryName=repo_name, triggers=[trigger]
    )["configurationId"]
    ctx.on_cleanup(
        lambda: cc.put_repository_triggers(repositoryName=repo_name, triggers=[])
    )
    stored = cc.get_repository_triggers(repositoryName=repo_name)
    assert [t["destinationArn"] for t in stored["triggers"]] == [fn_arn], (
        f"GetRepositoryTriggers reports destinationArns "
        f"{[t['destinationArn'] for t in stored['triggers']]!r}, expected exactly [{fn_arn!r}]"
    )

    # ---- Barrier: CodeCommit can reach and invoke this function, and its output reaches logs. ----
    tested = cc.test_repository_triggers(
        repositoryName=repo_name, triggers=[trigger]
    )
    assert tested["successfulExecutions"] == [trigger_name], (
        f"TestRepositoryTriggers reports successfulExecutions "
        f"{tested['successfulExecutions']!r} and failedExecutions "
        f"{tested['failedExecutions']!r}; the Lambda destination is not invocable, so nothing "
        f"below could distinguish 'not invoked' from 'not permitted'"
    )
    _await_records(
        logs,
        log_group,
        until=lambda got: any(r["eventName"] == "TriggerEventTest" for r in got),
        timeout_s=_LOG_TIMEOUT_S,
        reason=(
            "the synthetic TriggerEventTest invocation to appear in the function's log group -- "
            "the barrier proving CodeCommit -> Lambda -> CloudWatch Logs works end to end "
            "before any real write is made"
        ),
    )

    # ---- Three real ref updates: main, the unlisted branch, main again. ----
    first_main = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        filePath="one.txt",
        fileContent=b"one\n",
        parentCommitId=seed,
        commitMessage="first on main",
    )["commitId"]
    unlisted_commit = cc.put_file(
        repositoryName=repo_name,
        branchName="unlisted",
        filePath="unlisted.txt",
        fileContent=b"unlisted\n",
        parentCommitId=seed,
        commitMessage="on the unlisted branch",
    )["commitId"]
    second_main = cc.put_file(
        repositoryName=repo_name,
        branchName="main",
        filePath="two.txt",
        fileContent=b"two\n",
        parentCommitId=first_main,
        commitMessage="second on main",
    )["commitId"]
    assert len({seed, first_main, unlisted_commit, second_main}) == 4, (
        "the writes did not produce four distinct commit ids"
    )

    # The differential barrier: wait for the SECOND main commit, published after the unlisted
    # one, so once it is here the unlisted write has had strictly longer to produce a record.
    records = _await_records(
        logs,
        log_group,
        until=lambda got: any(
            _commits(r) and second_main in _commits(r) for r in got
        ),
        timeout_s=_LOG_TIMEOUT_S,
        reason=(
            f"the invocation for the second commit on main ({second_main}) to appear in the "
            "function's logs; it was written after the unlisted branch's commit, so its arrival "
            "bounds the window the unlisted commit had"
        ),
    )

    real = [r for r in records if r["eventName"] == "ReferenceChanges"]
    delivered_commits = [c for r in real for c in _commits(r)]
    assert first_main in delivered_commits, (
        f"the first commit on main ({first_main!r}) produced no invocation; the function was "
        f"handed commits {delivered_commits!r}"
    )
    assert second_main in delivered_commits, (
        f"the second commit on main ({second_main!r}) produced no invocation; the function was "
        f"handed commits {delivered_commits!r}"
    )

    # The payload names the ref and the exact commit created.
    matching = [r for r in real if first_main in _commits(r)]
    assert len(matching) == 1, (
        f"{len(matching)} payloads name the first commit {first_main!r}; expected exactly one"
    )
    record = matching[0]
    assert record["eventSource"] == "aws:codecommit", (
        f"the payload reports eventSource {record['eventSource']!r}, expected 'aws:codecommit'"
    )
    assert record["eventSourceARN"] == repo_arn, (
        f"the payload reports eventSourceARN {record['eventSourceARN']!r}, expected this "
        f"repository's ARN {repo_arn!r}"
    )
    assert record["eventTriggerName"] == trigger_name, (
        f"the payload reports eventTriggerName {record['eventTriggerName']!r}, expected "
        f"{trigger_name!r}"
    )
    assert record["eventTriggerConfigId"] == config_id, (
        f"the payload reports eventTriggerConfigId {record['eventTriggerConfigId']!r}, expected "
        f"the configurationId PutRepositoryTriggers returned, {config_id!r}"
    )
    assert record["codecommit"]["references"][0]["ref"] == "refs/heads/main", (
        f"the payload reports ref {record['codecommit']['references'][0]['ref']!r}, expected "
        f"the fully qualified 'refs/heads/main', not the short branch name"
    )

    # ---- Absence: the unlisted commit was written before second_main, whose record arrived. ----
    assert unlisted_commit not in delivered_commits, (
        f"the commit on the unlisted branch ({unlisted_commit!r}) invoked the function; the "
        f"trigger lists only 'main'. Every commit the function was handed: "
        f"{delivered_commits!r}"
    )
    refs = {r["codecommit"]["references"][0]["ref"] for r in real}
    assert refs == {"refs/heads/main"}, (
        f"the function was invoked for refs {sorted(refs)!r}; the trigger is scoped to main "
        f"alone"
    )


_HANDLER_SRC = '''import json


def handler(event, context):
    """Print the payload so CloudWatch Logs becomes the independent observer."""
    print("{marker}" + json.dumps(event))
    return "ok"
'''


def _create_function(ctx, lam, *, fn_name: str, role_arn: str, timeout_s: float) -> str:
    """Create the log-everything function, retrying only the IAM propagation window.

    RAISES on expiry: a role that never becomes assumable is a setup failure of this check, and
    an unusable consumer must not be mistaken for a producer that did not fire.
    """
    from botocore.exceptions import ClientError

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("handler.py", _HANDLER_SRC.replace("{marker}", _MARKER))

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="handler.handler",
                Code={"ZipFile": buf.getvalue()},
                Timeout=30,
                Tags={"sim2real": "cclam"},
            )["FunctionArn"]
        except ClientError as exc:
            last = exc
            # The only retryable case: IAM has not yet propagated the new role to Lambda.
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            time.sleep(5.0)
    raise AssertionError(
        f"CreateFunction({fn_name}) never succeeded within {timeout_s}s of waiting for the new "
        f"role {role_arn} to become assumable by Lambda; last error {last!r}"
    )


def _commits(record: dict) -> list[str]:
    """Commit ids named by a CodeCommit trigger record, or [] if it names none.

    Feeds membership tests and an ``assert ... not in`` absence check, so an empty default is the
    correct polarity: a record with no references cannot satisfy either side.
    """
    return [
        ref["commit"]
        for ref in record.get("codecommit", {}).get("references", [])
        if "commit" in ref
    ]


def _await_records(logs, log_group: str, *, until, timeout_s: float, reason: str) -> list[dict]:
    """Scan the function's log group for printed payloads until ``until`` holds.

    RAISES on expiry naming what it waited for and what it found. A missing log group is treated
    as "nothing yet" only until the deadline -- never as a reason to stop asserting.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    seen: list[dict] = []
    while True:
        seen = []
        try:
            token = None
            while True:
                kwargs = {
                    "logGroupName": log_group,
                    "filterPattern": f'"{_MARKER.strip()}"',
                }
                if token:
                    kwargs["nextToken"] = token
                page = logs.filter_log_events(**kwargs)
                for event in page["events"]:
                    message = event["message"]
                    start = message.find(_MARKER)
                    if start < 0:
                        continue
                    payload = json.loads(message[start + len(_MARKER):].strip())
                    seen.extend(payload["Records"])
                token = page.get("nextToken")
                if not token:
                    break
        except ClientError as exc:
            # Lambda creates the group on first invocation, so before then it does not exist.
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        if until(seen):
            return seen
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"waited {timeout_s}s for {reason} and it never happened. The function's log "
                f"group {log_group!r} yielded {len(seen)} record(s): "
                f"{[(r.get('eventName'), _commits(r)) for r in seen]!r}"
            )
        time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
