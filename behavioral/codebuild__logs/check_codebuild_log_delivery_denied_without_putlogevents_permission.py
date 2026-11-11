"""codebuild-log-delivery-denied-without-putlogevents-permission."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# ===== helpers =====
# _create_role returns the account id from the role ARN so the log-group ARNs can be scoped
# without an extra STS call.

_SCENARIO = "codebuild-logs-denied"
_IMAGE = "aws/codebuild/standard:7.0"


def _delete_role(iam, role_name):
    """Delete an IAM role, removing its inline policies first (cleanup path: best-effort)."""
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_role(ctx):
    """Mint a CodeBuild-assumable role with no permissions yet. Returns
    (role_name, role_arn, account_id) - the account id comes off the role's own ARN."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-codebuild-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "codebuild.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    return role_name, arn, arn.split(":")[4]


def _put_policy(ctx, role_name, statements):
    ctx.client("iam").put_role_policy(
        RoleName=role_name,
        PolicyName="codebuild-inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    # IAM propagation exposes no condition to poll; the bounded, deadlined retry inside
    # _create_project is what makes this correct.


def _create_project(cb, ctx, name, role_arn, buildspec, **over):
    """CreateProject on NO_SOURCE + an inline buildspec, retrying through IAM trust-policy
    propagation; registers teardown immediately on success. Returns the project dict."""
    args = {
        "name": name,
        "source": {"type": "NO_SOURCE", "buildspec": buildspec},
        "artifacts": {"type": "NO_ARTIFACTS"},
        "cache": {"type": "NO_CACHE"},
        "environment": {"type": "LINUX_CONTAINER", "image": _IMAGE,
                        "computeType": "BUILD_GENERAL1_SMALL"},
        "serviceRole": role_arn,
        "timeoutInMinutes": 5,
        "tags": [{"key": "sim2real", "value": _SCENARIO}],
    }
    args.update(over)
    deadline = time.monotonic() + 120
    while True:
        try:
            proj = cb.create_project(**args)["project"]
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            msg = (err.get("Message") or "").lower()
            transient_role = err.get("Code") == "InvalidInputException" and (
                "assume" in msg or "not authorized" in msg)
            if transient_role and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: cb.delete_project(name=proj["name"]))
    return proj


def _stop(cb, build_id):
    try:
        cb.stop_build(id=build_id)
    except ClientError:
        pass  # already terminal, or the project is gone - nothing left to bill


def _start_build_with_stop_registered(cb, ctx, **kwargs):
    """Register the StopBuild cleanup BEFORE issuing StartBuild, so a build that starts and
    then trips an assertion still gets stopped instead of billing its whole timeout."""
    holder = {"id": None}
    ctx.on_cleanup(lambda: holder["id"] and _stop(cb, holder["id"]))
    resp = cb.start_build(**kwargs)
    holder["id"] = resp["build"]["id"]
    return resp["build"]


def _poll_build_terminal(cb, build_id, *, timeout_s, interval_s=3.0):
    """Poll BatchGetBuilds until buildComplete, bounded by a deadline. Returns the terminal
    Build dict, or None if the deadline passed while it was still running."""
    deadline = time.monotonic() + timeout_s
    while True:
        got = cb.batch_get_builds(ids=[build_id])
        builds = got.get("builds", [])
        assert builds, f"BatchGetBuilds lost build {build_id!r}: {got!r}"
        last = builds[0]
        if last.get("buildComplete") is True:
            return last
        if time.monotonic() >= deadline:
            return None
        time.sleep(interval_s)


def _phases(build):
    return [(p.get("phaseType"), p.get("phaseStatus")) for p in build.get("phases", [])]


def _group_streams(logs, group):
    """Every stream name in the group, paginated."""
    names = []
    token = None
    while True:
        kwargs = {"logGroupName": group}
        if token:
            kwargs["nextToken"] = token
        page = logs.describe_log_streams(**kwargs)
        names.extend(s["logStreamName"] for s in page.get("logStreams", []))
        token = page.get("nextToken")
        if not token:
            return sorted(names)


def _group_messages(logs, group):
    """Every event message anywhere in the group, in delivery order, paginated."""
    messages = []
    token = None
    while True:
        kwargs = {"logGroupName": group}
        if token:
            kwargs["nextToken"] = token
        page = logs.filter_log_events(**kwargs)
        messages.extend(e["message"] for e in page.get("events", []))
        token = page.get("nextToken")
        if not token:
            return messages


def _poll_for_marker(logs, group, marker, *, timeout_s):
    """Poll the whole group until `marker` has been delivered, bounded. Returns the messages
    seen on the last pass so the caller can quote what really arrived."""
    deadline = time.monotonic() + timeout_s
    while True:
        messages = _group_messages(logs, group)
        if any(marker in m for m in messages):
            return messages
        if time.monotonic() >= deadline:
            return messages
        time.sleep(3)


# ===== check =====

CHECK = "codebuild-log-delivery-denied-without-putlogevents-permission"
GROUP = 'logging'
SERVICES = ['codebuild', 'logs']


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e",
      "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A project whose role holds logs:PutLogEvents only on a DIFFERENT group delivers nothing to its
    configured group while a permitted sibling keeps delivering there around it, and granting the
    missing permission makes its very next build deliver."""
    cb = ctx.client("codebuild")
    logs = ctx.client("logs")
    iam = ctx.client("iam")

    group = ctx.unique_name("sim2real-behav-cb-lg-")
    logs.create_log_group(logGroupName=group, tags={"sim2real": _SCENARIO})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    logs.put_retention_policy(logGroupName=group, retentionInDays=1)
    decoy = ctx.unique_name("sim2real-behav-cb-decoy-lg-")

    buildspec = (
        "version: 0.2\n"
        "phases:\n"
        "  build:\n"
        "    commands:\n"
        '      - echo "$SIM2REAL_MARKER"\n'
    )

    # Both roles are minted BEFORE any build runs, so no propagation delta can explain the
    # difference between them - the only difference is which group the logs grant names.
    ok_role, ok_arn, account = _create_role(ctx)
    bad_role, bad_arn, _ = _create_role(ctx)

    def _logs_stmt(target):
        arn = f"arn:aws:logs:{ctx.region}:{account}:log-group:{target}"
        return [{"Effect": "Allow",
                 "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                 "Resource": [arn, f"{arn}:*"]}]

    _put_policy(ctx, ok_role, _logs_stmt(group))
    _put_policy(ctx, bad_role, _logs_stmt(decoy))

    ok_stream = "sim2real-ok"
    bad_stream = "sim2real-bad"

    def _logs_config(stream):
        return {"cloudWatchLogs": {"status": "ENABLED", "groupName": group,
                                   "streamName": stream},
                "s3Logs": {"status": "DISABLED"}}

    ok_project = ctx.unique_name("sim2real-behav-proj-oklog-")
    bad_project = ctx.unique_name("sim2real-behav-proj-badlog-")
    _create_project(cb, ctx, ok_project, ok_arn, buildspec,
                    logsConfig=_logs_config(ok_stream))
    _create_project(cb, ctx, bad_project, bad_arn, buildspec,
                    logsConfig=_logs_config(bad_stream))

    def _run(project, marker):
        started = _start_build_with_stop_registered(
            cb, ctx, projectName=project,
            environmentVariablesOverride=[
                {"name": "SIM2REAL_MARKER", "value": marker, "type": "PLAINTEXT"}])
        final = _poll_build_terminal(cb, started["id"], timeout_s=240)
        assert final is not None, f"build {started['id']!r} never reported buildComplete"
        return final

    # --- barrier: the permitted project delivers into the group ---------------------
    ok_marker_1 = ctx.unique_name("sim2real-ok-one-")
    ok_1 = _run(ok_project, ok_marker_1)
    assert ok_1["buildStatus"] == "SUCCEEDED", (
        f"the permitted control build was {ok_1['buildStatus']!r}; phases={_phases(ok_1)!r}"
    )
    seen = _poll_for_marker(logs, group, ok_marker_1, timeout_s=180)
    assert any(ok_marker_1 in m for m in seen), (
        f"the permitted build's marker {ok_marker_1!r} never reached {group!r}, so the "
        f"barrier itself did not hold; {len(seen)} events: {seen[-12:]!r}"
    )

    # --- break exactly one thing: the grant names the decoy group ------------------
    bad_marker = ctx.unique_name("sim2real-bad-")
    bad = _run(bad_project, bad_marker)
    assert bad["buildStatus"] == "FAILED", (
        f"a build that cannot write to its configured log group must FAIL, got "
        f"{bad['buildStatus']!r}; phases={_phases(bad)!r}; contexts="
        f"{[p.get('contexts') for p in bad.get('phases', [])]!r}"
    )
    # streamName is a PREFIX - the resolved stream is "<prefix>/<build uuid>" - so the
    # absence has to be tested by prefix. A plain `not in` on the prefix would be vacuous.
    streams_after_bad = _group_streams(logs, group)
    assert [s for s in streams_after_bad if s.startswith(bad_stream + "/")] == [], (
        f"the refused build created its stream under {bad_stream + '/'!r} anyway; the group "
        f"holds {streams_after_bad!r}"
    )
    messages_after_bad = _group_messages(logs, group)
    assert not any(bad_marker in m for m in messages_after_bad), (
        f"the refused build's marker {bad_marker!r} was delivered to {group!r} regardless of "
        f"the missing grant; {len(messages_after_bad)} events: {messages_after_bad[-12:]!r}"
    )

    # --- the good side keeps delivering, so the absence is not a lull -------------
    ok_marker_2 = ctx.unique_name("sim2real-ok-two-")
    ok_2 = _run(ok_project, ok_marker_2)
    assert ok_2["buildStatus"] == "SUCCEEDED", (
        f"the second permitted build was {ok_2['buildStatus']!r}; phases={_phases(ok_2)!r}"
    )
    seen_2 = _poll_for_marker(logs, group, ok_marker_2, timeout_s=180)
    assert any(ok_marker_2 in m for m in seen_2), (
        f"the group stopped accepting writes mid-check: {ok_marker_2!r} never arrived; "
        f"{len(seen_2)} events: {seen_2[-12:]!r}"
    )
    late_streams = _group_streams(logs, group)
    assert [s for s in late_streams if s.startswith(bad_stream + "/")] == [], (
        f"the refused build's stream appeared late; the group holds {late_streams!r}"
    )

    # --- repair the one broken thing: the same project must then deliver ----------
    iam.put_role_policy(
        RoleName=bad_role, PolicyName="codebuild-inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17",
                                   "Statement": _logs_stmt(group)}))
    repaired_marker = ctx.unique_name("sim2real-repaired-")
    deadline = time.monotonic() + 240
    repaired = _run(bad_project, repaired_marker)
    while repaired["buildStatus"] != "SUCCEEDED" and time.monotonic() < deadline:
        # the grant is eventually consistent; retry the build, never assert off a sleep
        repaired = _run(bad_project, repaired_marker)
    assert repaired["buildStatus"] == "SUCCEEDED", (
        f"after granting logs:PutLogEvents on {group!r} the same project must build, got "
        f"{repaired['buildStatus']!r}; phases={_phases(repaired)!r}"
    )
    seen_3 = _poll_for_marker(logs, group, repaired_marker, timeout_s=180)
    assert any(repaired_marker in m for m in seen_3), (
        f"the repaired build's marker {repaired_marker!r} still did not reach {group!r}; "
        f"{len(seen_3)} events: {seen_3[-12:]!r}"
    )
    final_streams = _group_streams(logs, group)
    assert f"{bad_stream}/{repaired['id'].split(':')[-1]}" in final_streams, (
        f"the repaired build should have created "
        f"{bad_stream}/{repaired['id'].split(':')[-1]!r}; the group holds {final_streams!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
