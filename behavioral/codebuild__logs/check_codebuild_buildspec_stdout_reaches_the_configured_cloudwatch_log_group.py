"""codebuild-buildspec-stdout-reaches-the-configured-cloudwatch-log-group."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_SCENARIO = "codebuild-logs-delivery"
_IMAGE = "aws/codebuild/standard:7.0"


def _delete_role(iam, role_name):
    """Delete an IAM role after its inline policies, tolerating NoSuchEntity."""
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
    # IAM propagation has no condition to poll; _create_project retries through it.


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


def _delivered_messages(logs, group, stream):
    """Every event message in one stream, in delivery order, paginated."""
    messages = []
    token = None
    while True:
        kwargs = {"logGroupName": group, "logStreamNames": [stream],
                  "startFromHead": True}
        if token:
            kwargs["nextToken"] = token
        page = logs.filter_log_events(**kwargs)
        messages.extend(e["message"] for e in page.get("events", []))
        token = page.get("nextToken")
        if not token:
            return messages


def _poll_for_markers(logs, group, stream, markers, *, timeout_s):
    """Poll the delivered events until every marker has arrived, bounded. Returns the last
    listing so the caller can quote what really arrived."""
    deadline = time.monotonic() + timeout_s
    while True:
        messages = _delivered_messages(logs, group, stream)
        blob = "\n".join(messages)
        if all(m in blob for m in markers):
            return messages
        if time.monotonic() >= deadline:
            return messages
        time.sleep(3)


# ===== check =====

CHECK = "codebuild-buildspec-stdout-reaches-the-configured-cloudwatch-log-group"
GROUP = 'logging'
SERVICES = ['codebuild', 'logs']


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e",
      "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """Markers echoed in the build and post_build phases reach the project's log group in phase order,
    in the one stream the build reports: the configured streamName prefix plus this build's id.
    """
    cb = ctx.client("codebuild")
    logs = ctx.client("logs")

    group = ctx.unique_name("sim2real-behav-cb-lg-")
    logs.create_log_group(logGroupName=group, tags={"sim2real": _SCENARIO})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    logs.put_retention_policy(logGroupName=group, retentionInDays=1)

    role_name, role_arn, account = _create_role(ctx)
    group_arn = f"arn:aws:logs:{ctx.region}:{account}:log-group:{group}"
    _put_policy(ctx, role_name, [
        {"Effect": "Allow",
         "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": [group_arn, f"{group_arn}:*"]},
    ])

    build_marker = ctx.unique_name("sim2real-build-phase-")
    post_marker = ctx.unique_name("sim2real-post-phase-")
    buildspec = (
        "version: 0.2\n"
        "phases:\n"
        "  build:\n"
        "    commands:\n"
        '      - echo "$SIM2REAL_BUILD_MARKER"\n'
        "  post_build:\n"
        "    commands:\n"
        '      - echo "$SIM2REAL_POST_MARKER"\n'
    )

    stream_prefix = "sim2real-stream"
    name = ctx.unique_name("sim2real-behav-proj-log-")
    _create_project(
        cb, ctx, name, role_arn, buildspec,
        logsConfig={"cloudWatchLogs": {"status": "ENABLED", "groupName": group,
                                       "streamName": stream_prefix},
                    "s3Logs": {"status": "DISABLED"}},
    )

    started = _start_build_with_stop_registered(
        cb, ctx, projectName=name,
        environmentVariablesOverride=[
            {"name": "SIM2REAL_BUILD_MARKER", "value": build_marker, "type": "PLAINTEXT"},
            {"name": "SIM2REAL_POST_MARKER", "value": post_marker, "type": "PLAINTEXT"},
        ])
    build = _poll_build_terminal(cb, started["id"], timeout_s=240)
    assert build is not None, f"build {started['id']!r} never reported buildComplete"
    assert build["buildStatus"] == "SUCCEEDED", (
        f"build was {build['buildStatus']!r}; phases={_phases(build)!r}"
    )

    reported = build.get("logs") or {}
    assert reported.get("groupName") == group, (
        f"the build must name the group it was configured with, reported {reported!r}"
    )
    # logsConfig streamName is a prefix: events land in "<prefix>/<build uuid>"; the build echoes
    # the prefix under logs.cloudWatchLogs while logs.streamName holds the resolved name.
    stream = reported.get("streamName")
    assert stream == f"{stream_prefix}/{build['id'].split(':')[-1]}", (
        f"the resolved stream must be the configured prefix plus this build's own id, "
        f"reported {stream!r} for build {build['id']!r}; whole logs block {reported!r}"
    )
    assert reported.get("cloudWatchLogs", {}).get("streamName") == stream_prefix, (
        f"the build must echo back the streamName prefix it was configured with, reported "
        f"{reported.get('cloudWatchLogs')!r}"
    )

    delivered = _poll_for_markers(logs, group, stream, (build_marker, post_marker),
                                 timeout_s=180)
    blob = "\n".join(delivered)
    assert build_marker in blob, (
        f"{build_marker!r} never appeared in {group!r}/{stream!r}; {len(delivered)} events "
        f"were delivered: {delivered[-12:]!r}"
    )
    assert post_marker in blob, (
        f"{post_marker!r} is missing from the delivered log events, so the post_build phase "
        f"output was not logged; {len(delivered)} events: {delivered[-12:]!r}"
    )
    assert blob.index(build_marker) < blob.index(post_marker), (
        f"post_build output preceded build output in the delivered log: {delivered!r}"
    )

    streams = []
    token = None
    while True:
        kwargs = {"logGroupName": group}
        if token:
            kwargs["nextToken"] = token
        page = logs.describe_log_streams(**kwargs)
        streams.extend(s["logStreamName"] for s in page.get("logStreams", []))
        token = page.get("nextToken")
        if not token:
            break
    assert streams == [stream], (
        f"the configured stream should be the only one in the group, group holds {streams!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
