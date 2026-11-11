"""codebuild-parameter-store-env-var-resolves-and-its-exact-value-is-masked-in-the-log."""
from __future__ import annotations

import hashlib
import json
import random
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_SCENARIO = "codebuild-param-store-masking"
_IMAGE = "aws/codebuild/standard:7.0"


def _delete_role(iam, role_name):
    """Delete an IAM role, removing its inline policies first."""
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
    """Create a CodeBuild-assumable role with no permissions yet; policies are put later because
    they name ARNs that do not exist yet. Returns (role_name, role_arn, account_id from the ARN)."""
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
    # Trust propagation exposes no condition to poll, so this bounded retry IS the wait.
    deadline = time.monotonic() + 180
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


def _get_build(cb, build_id):
    got = cb.batch_get_builds(ids=[build_id])
    builds = got.get("builds", [])
    assert builds, (
        f"BatchGetBuilds lost build {build_id!r}: buildsNotFound="
        f"{got.get('buildsNotFound')!r}"
    )
    return builds[0]


def _poll_build_terminal(cb, build_id, *, timeout_s, interval_s=5.0):
    """Poll BatchGetBuilds until buildComplete; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = _get_build(cb, build_id)
        if last.get("buildComplete") is True:
            return last
        assert time.monotonic() < deadline, (
            f"build {build_id!r} never reported buildComplete within {timeout_s}s; last "
            f"buildStatus={last.get('buildStatus')!r} currentPhase="
            f"{last.get('currentPhase')!r}"
        )
        time.sleep(interval_s)


def _stream_messages(logs, group, stream):
    """Every event message in one stream, in delivery order, paginated."""
    messages = []
    token = None
    while True:
        kwargs = {"logGroupName": group, "logStreamName": stream, "startFromHead": True}
        if token:
            kwargs["nextToken"] = token
        page = logs.get_log_events(**kwargs)
        events = page.get("events", [])
        messages.extend(e["message"] for e in events)
        nxt = page.get("nextForwardToken")
        if not events or nxt == token:
            return messages
        token = nxt


def _poll_for_markers(logs, group, stream, markers, *, timeout_s, interval_s=3.0):
    """Poll one stream until every marker has been delivered, bounded; return the last messages.

    Returns rather than raises on timeout so the caller's assertions name the missing marker."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            messages = _stream_messages(logs, group, stream)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            messages = []  # the stream has not been created yet
        blob = "\n".join(messages)
        if all(m in blob for m in markers):
            return messages
        if time.monotonic() >= deadline:
            return messages
        time.sleep(interval_s)


def _phases(build):
    return [(p.get("phaseType"), p.get("phaseStatus")) for p in build.get("phases", [])]


def _secret_token(n):
    """A high-entropy value with no substring that could occur incidentally in a build log."""
    alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits
    return "".join(random.SystemRandom().choice(alphabet) for _ in range(n))


CHECK = "codebuild-parameter-store-env-var-resolves-and-its-exact-value-is-masked-in-the-log"
GROUP = 'environment'
SERVICES = ['codebuild', 'logs']


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e",
      "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PARAMETER_STORE env var resolves inside the build (digest and reversed value prove it),
    while its exact value never appears in the CloudWatch Logs stream or the BatchGetBuilds/Projects
    responses, and a same-shape PLAINTEXT variable echoed alongside does arrive verbatim.

    Reference: https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html
    """
    cb = ctx.client("codebuild")
    logs = ctx.client("logs")
    ssm = ctx.client("ssm")

    # Two values minted here, of the SAME length, so nothing about the assertions can be
    # explained by their shape - only by which env-var TYPE carried them.
    secret_value = _secret_token(28)
    plain_value = _secret_token(28)
    assert secret_value != plain_value, "the two minted values must differ"

    param_name = "/sim2real/" + ctx.unique_name("behav-cb-param-")
    assert len(param_name) != len(secret_value), (
        f"the parameter NAME and its VALUE must differ in length so the in-container length "
        f"assertion cannot pass on the name: name={len(param_name)} value={len(secret_value)}"
    )
    ssm.put_parameter(Name=param_name, Value=secret_value, Type="String",
                      Tags=[{"Key": "sim2real", "Value": _SCENARIO}])
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=param_name))

    group = ctx.unique_name("sim2real-behav-cb-mask-lg-")
    logs.create_log_group(logGroupName=group, tags={"sim2real": _SCENARIO})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    logs.put_retention_policy(logGroupName=group, retentionInDays=1)

    role_name, role_arn, account = _create_role(ctx)
    log_arn = f"arn:aws:logs:{ctx.region}:{account}:log-group:{group}"
    param_arn = f"arn:aws:ssm:{ctx.region}:{account}:parameter{param_name}"
    _put_policy(ctx, role_name, [
        {"Effect": "Allow",
         "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": [log_arn, f"{log_arn}:*"]},
        # Both spellings granted so a missing grant cannot be mistaken for a masking result.
        {"Effect": "Allow",
         "Action": ["ssm:GetParameter", "ssm:GetParameters"],
         "Resource": [param_arn]},
    ])

    # `rev` reverses the value; the docs name reversing as a transform that is NOT masked.
    # `${#VAR}` reports the resolved value's length, which differs from the parameter name's.
    buildspec = (
        "version: 0.2\n"
        "env:\n"
        "  exported-variables:\n"
        "    - SIM2REAL_DIGEST\n"
        "phases:\n"
        "  build:\n"
        "    commands:\n"
        '      - echo "SIM2REAL_RAW:${SIM2REAL_PARAM}"\n'
        '      - echo "SIM2REAL_REV:$(printf \'%s\' "${SIM2REAL_PARAM}" | rev)"\n'
        '      - echo "SIM2REAL_LEN:${#SIM2REAL_PARAM}"\n'
        '      - echo "SIM2REAL_PLAIN:${SIM2REAL_PLAIN}"\n'
        '      - export SIM2REAL_DIGEST="$(printf \'%s\' "${SIM2REAL_PARAM}"'
        " | sha256sum | cut -d' ' -f1)\"\n"
    )

    stream_prefix = "sim2real-mask"
    name = ctx.unique_name("sim2real-behav-proj-mask-")
    _create_project(
        cb, ctx, name, role_arn, buildspec,
        environment={"type": "LINUX_CONTAINER", "image": _IMAGE,
                     "computeType": "BUILD_GENERAL1_SMALL",
                     "environmentVariables": [
                         {"name": "SIM2REAL_PARAM", "value": param_name,
                          "type": "PARAMETER_STORE"},
                         {"name": "SIM2REAL_PLAIN", "value": plain_value,
                          "type": "PLAINTEXT"},
                     ]},
        logsConfig={"cloudWatchLogs": {"status": "ENABLED", "groupName": group,
                                       "streamName": stream_prefix},
                    "s3Logs": {"status": "DISABLED"}},
    )

    started = _start_build_with_stop_registered(cb, ctx, projectName=name)
    build = _poll_build_terminal(cb, started["id"], timeout_s=360)

    assert build["buildStatus"] == "SUCCEEDED", (
        f"the build must succeed for its log to be evidence; got {build['buildStatus']!r}; "
        f"phases={_phases(build)!r}; "
        f"contexts={[p.get('contexts') for p in build.get('phases', [])]!r}"
    )

    # --- resolution, proven API-side by a digest the container computed --------------
    exported = {v["name"]: v["value"]
                for v in build.get("exportedEnvironmentVariables") or []}
    expected_digest = hashlib.sha256(secret_value.encode()).hexdigest()
    assert exported.get("SIM2REAL_DIGEST") == expected_digest, (
        f"the container must have held the RESOLVED parameter value, whose sha256 is "
        f"{expected_digest!r}; it exported {exported.get('SIM2REAL_DIGEST')!r}. A target that "
        f"passed the parameter NAME through unresolved would report "
        f"{hashlib.sha256(param_name.encode()).hexdigest()!r}. All exported: {exported!r}"
    )

    # --- the delivered log stream is the destination ---
    reported = build.get("logs") or {}
    assert reported.get("groupName") == group, (
        f"the build must report the log group it was configured with ({group!r}), it reports "
        f"{reported.get('groupName')!r}; full logs block {reported!r}"
    )
    # streamName is a prefix; the resolved stream is <prefix>/<build uuid>.
    stream = f"{stream_prefix}/{build['id'].split(':')[-1]}"
    rev_marker = "SIM2REAL_REV:" + secret_value[::-1]
    plain_marker = "SIM2REAL_PLAIN:" + plain_value
    len_marker = "SIM2REAL_LEN:" + str(len(secret_value))
    messages = _poll_for_markers(
        logs, group, stream, (rev_marker, plain_marker, len_marker), timeout_s=180)
    blob = "\n".join(messages)

    # Positive control A: the PLAINTEXT twin, same length, same buildspec, same stream.
    assert plain_marker in blob, (
        f"the PLAINTEXT variable's value must reach the log stream verbatim - without this the "
        f"absence of the parameter value proves nothing, because a target delivering no logs at "
        f"all would score green. {plain_marker!r} is not in the {len(messages)} delivered "
        f"events; last few: {messages[-12:]!r}"
    )
    # Positive control B: the documented transform escape hatch. Its presence proves the
    # container held the real value AND that the log pipeline carries derived forms.
    assert rev_marker in blob, (
        f"the REVERSED value is documented as a transform that masking does NOT match, so it "
        f"must arrive verbatim: expected {rev_marker!r} among the {len(messages)} delivered "
        f"events; last few: {messages[-12:]!r}"
    )
    assert len_marker in blob, (
        f"the container must report the resolved value's length ({len(secret_value)}), not the "
        f"parameter name's ({len(param_name)}); expected {len_marker!r} among the "
        f"{len(messages)} delivered events; last few: {messages[-12:]!r}"
    )

    # The raw line WAS delivered - so the masking elided a value, it did not drop an event.
    raw_lines = [m for m in messages if "SIM2REAL_RAW:" in m]
    assert raw_lines, (
        f"the buildspec echoes a line prefixed SIM2REAL_RAW:, and that line must be delivered "
        f"with the value masked rather than dropped wholesale; the {len(messages)} delivered "
        f"events contain no such prefix. Last few: {messages[-12:]!r}"
    )

    # --- the masking contract: the EXACT stored value is nowhere in the stream ------
    assert secret_value not in blob, (
        f"the exact PARAMETER_STORE value must be masked in the build log, but it appears in a "
        f"delivered event. The offending lines were "
        f"{[m for m in messages if secret_value in m][:3]!r} (value redacted from this message "
        f"is {len(secret_value)} chars; its sha256 is {expected_digest!r})"
    )

    # --- and not in the CodeBuild API surface either ---------------------------
    assert secret_value not in json.dumps(build, default=str), (
        "the resolved PARAMETER_STORE value must not appear anywhere in the BatchGetBuilds "
        "response; it did (response body withheld from this message on purpose)"
    )
    stored = cb.batch_get_projects(names=[name])["projects"]
    assert len(stored) == 1, (
        f"BatchGetProjects must return exactly the one project {name!r}, returned "
        f"{[p.get('name') for p in stored]!r}"
    )
    assert secret_value not in json.dumps(stored[0], default=str), (
        "the resolved PARAMETER_STORE value must not appear anywhere in the BatchGetProjects "
        "response; it did (response body withheld from this message on purpose)"
    )
    stored_vars = [(v["name"], v["value"], v.get("type"))
                   for v in stored[0]["environment"]["environmentVariables"]]
    assert (("SIM2REAL_PARAM", param_name, "PARAMETER_STORE") in stored_vars
            and ("SIM2REAL_PLAIN", plain_value, "PLAINTEXT") in stored_vars), (
        f"the project must store the parameter NAME for the typed variable and the literal for "
        f"the PLAINTEXT one; it stores {stored_vars!r}"
    )

    # The stream this check read is the only one the build created (nothing leaked sideways).
    described = []
    token = None
    while True:
        kwargs = {"logGroupName": group}
        if token:
            kwargs["nextToken"] = token
        page = logs.describe_log_streams(**kwargs)
        described.extend(s["logStreamName"] for s in page.get("logStreams", []))
        token = page.get("nextToken")
        if not token:
            break
    assert sorted(described) == [stream], (
        f"the group must hold exactly the one stream this build wrote ({stream!r}); it holds "
        f"{sorted(described)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
