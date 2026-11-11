"""update-pipe-filter-criteria-takes-effect-on-a-running-pipe-and-reverts."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-pipe-filter-criteria-takes-effect-on-a-running-pipe-and-reverts"
GROUP = "state-machine"
SERVICES = ["pipes"]



@tags("axis:negative-delivery", "cap:c2", "cap:c4", "concern:data-plane", "concern:eventing",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdatePipe on a RUNNING pipe re-installs FilterCriteria: a newly excluded shape stops being
    delivered while an admitted twin keeps flowing, and reverting the filter brings the excluded
    shape back and excludes the other again.
    """
    pipes_client = ctx.client("pipes")
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    source = _create_queue(ctx, VisibilityTimeout="60")
    target = _create_queue(ctx)
    role = _create_pipe_role(
        ctx,
        _sqs_read_statements(source["arn"])
        + [{"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target["arn"]}],
    )
    assert account in role["arn"], (
        f"execution role ARN {role['arn']!r} must belong to the STS-asserted account {account!r}"
    )

    run_id = _xname(ctx, "upd")
    # v1 admits alpha and beta; v2 admits beta and gamma. beta is the twin admitted by BOTH, so it
    # is a live control in every phase. alpha and gamma each exist only under one version.
    v1 = {"body": {"kind": ["alpha", "beta"]}}
    v2 = {"body": {"kind": ["beta", "gamma"]}}
    def source_params(pattern: dict[str, Any]) -> dict[str, Any]:
        return {
            "SqsQueueParameters": {"BatchSize": 1},
            "FilterCriteria": {"Filters": [{"Pattern": json.dumps(pattern)}]},
        }

    def _send(kind: str, tag: str) -> str:
        marker = f"{run_id}-{tag}"
        sqs.send_message(
            QueueUrl=source["url"], MessageBody=json.dumps({"kind": kind, "marker": marker})
        )
        return marker

    def _stored_pattern(described: dict[str, Any]) -> dict[str, Any] | None:
        """The filter DescribePipe currently reports, or None if it reports none at all.

        None rather than a KeyError, so a dropped FilterCriteria surfaces as the poll's timeout.
        """
        params = described["SourceParameters"]
        if "FilterCriteria" not in params:
            return None
        return json.loads(params["FilterCriteria"]["Filters"][0]["Pattern"])

    def _install(pattern: dict[str, Any], label: str) -> None:
        pipes_client.update_pipe(
            Name=pipe, RoleArn=role["arn"], SourceParameters=source_params(pattern)
        )
        _poll_until(
            lambda: pipes_client.describe_pipe(Name=pipe),
            lambda d: d["CurrentState"] == "RUNNING" and _stored_pattern(d) == pattern,
            timeout_s=300.0,
            interval_s=5.0,
            description=(
                f"pipe {pipe!r} back to CurrentState==RUNNING with the {label} filter stored after "
                f"UpdatePipe (expected pattern {pattern!r})"
            ),
        )

    pipe = _create_pipe(
        ctx,
        source=source["arn"],
        target=target["arn"],
        role_arn=role["arn"],
        SourceParameters=source_params(v1),
    )

    # Positive control under v1. alpha is admitted by v1 and by nothing else.
    alpha1 = _send("alpha", "A1-ALPHA")
    _await_source_fully_processed(
        ctx, source["url"], timeout_s=420.0, why=f"the v1 control record handed to pipe {pipe!r}"
    )
    _, latency = _await_marker(
        ctx,
        target["url"],
        alpha1,
        timeout_s=180.0,
        description=(
            f"the v1-admitted control record {alpha1!r} reaching the target of pipe {pipe!r}; "
            f"nothing below means anything if the pipe never delivered under its original filter"
        ),
    )

    # SourceParameters on UpdatePipe replaces FilterCriteria; SqsQueueParameters is restated
    # because a mismatched source-parameter block is refused.
    _install(v2, "tightened v2")

    # gamma is admitted only by v2, so its arrival proves the poller applies v2.
    gamma_latency = _await_probe(
        ctx,
        target["url"],
        lambda n: _send("gamma", f"B0-GAMMAPROBE{n:03d}"),
        timeout_s=900.0,
        description=(
            f"a gamma record -- admitted by v2 and refused by v1 -- reaching the target of pipe "
            f"{pipe!r}, which is the proof that UpdatePipe's new FilterCriteria is what the poller "
            f"is applying"
        ),
    )
    # An SQS source can run several concurrent pollers and gamma only proves ONE is on v2; a
    # straggler can still apply v1, so give siblings time on the order of the update latency.
    _drain(ctx, target["url"], window_s=max(60.0, 3.0 * gamma_latency))

    # Only now can alpha be sent without racing the update: the poller is demonstrably on v2.
    alpha2 = _send("alpha", "B1-ALPHA")
    beta2 = _send("beta", "B2-BETA")
    _await_source_fully_processed(
        ctx,
        source["url"],
        timeout_s=420.0,
        why=f"the v2-phase alpha/beta pair handed to pipe {pipe!r}",
    )
    phase_b, beta_latency = _await_marker(
        ctx,
        target["url"],
        beta2,
        timeout_s=180.0,
        description=(
            f"the twin record {beta2!r} -- admitted by BOTH filter versions -- reaching the target "
            f"in the same instant as the withheld alpha, which is what makes the absence a "
            f"property of the filter rather than of a dead pipe"
        ),
    )
    phase_b.extend(_drain(ctx, target["url"], window_s=max(15.0, 3.0 * beta_latency)))
    b_bodies = [m["Body"] for m in phase_b]
    assert not any(alpha2 in b for b in b_bodies), (
        f"pipe {pipe!r} delivered {alpha2!r} after UpdatePipe replaced its filter with {v2!r}, "
        f"which no longer admits kind=alpha. The twin {beta2!r} arrived after "
        f"{beta_latency:.1f}s and the source is fully drained, so the update was stored but not "
        f"applied. Target saw: {b_bodies!r}"
    )

    # Restore v1 and demand the withheld shape back.
    _install(v1, "restored v1")
    # As after the tightening: one alpha probe proves a poller is back on v1, then sibling
    # pollers get as long again to converge before gamma's exclusion is tested.
    alpha_probe_latency = _await_probe(
        ctx,
        target["url"],
        lambda n: _send("alpha", f"C0-ALPHAPROBE{n:03d}"),
        timeout_s=900.0,
        description=(
            f"an alpha record -- admitted by v1 and refused by v2 -- reaching the target of pipe "
            f"{pipe!r}, which is the proof that the restored FilterCriteria is what the poller "
            f"is applying"
        ),
    )
    _drain(ctx, target["url"], window_s=max(60.0, 3.0 * alpha_probe_latency))
    alpha3 = _send("alpha", "C1-ALPHA")
    gamma3 = _send("gamma", "C2-GAMMA")
    _await_source_fully_processed(
        ctx,
        source["url"],
        timeout_s=420.0,
        why=f"the restored-v1 alpha/gamma pair handed to pipe {pipe!r}",
    )
    phase_c, alpha3_latency = _await_marker(
        ctx,
        target["url"],
        alpha3,
        timeout_s=300.0,
        description=(
            f"the previously WITHHELD shape {alpha3!r} being delivered again once UpdatePipe "
            f"restored {v1!r}; a target that faked the tightening by simply doing nothing fails "
            f"here"
        ),
    )
    phase_c.extend(_drain(ctx, target["url"], window_s=max(15.0, 3.0 * alpha3_latency)))
    c_bodies = [m["Body"] for m in phase_c]
    # The revert must be a real replacement, not "now everything flows".
    assert not any(gamma3 in b for b in c_bodies), (
        f"pipe {pipe!r} delivered {gamma3!r} after the filter was restored to {v1!r}, which does "
        f"not admit kind=gamma. The restore therefore added the old pattern instead of replacing "
        f"the tightened one, or the pipe stopped filtering altogether. {alpha3!r} arrived after "
        f"{alpha3_latency:.1f}s (first-phase control latency was {latency:.1f}s). Target saw: "
        f"{c_bodies!r}"
    )

_PREFIX = "sim2real-pipesgap-"
_MANAGED = {"sim2real:managed": "true", "sim2real:prefix": _PREFIX.rstrip("-")}


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name so any leftover can be found by tag or prefix."""
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED.items()]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    """Poll probe() until predicate(result) is truthy; return that result.

    Raises on timeout rather than returning the last value.
    """
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        if interval_s > 0:
            time.sleep(interval_s)
    raise AssertionError(
        f"{description}: not satisfied within {timeout_s}s. Last observed value: {last!r}"
    )


def _create_queue(ctx, *, fifo: bool = False, **attrs: str) -> dict[str, str]:
    """Create a tagged SQS queue, register its teardown, and return {name,url,arn}."""
    sqs = ctx.client("sqs")
    base = _xname(ctx, "q")
    name = f"{base}.fifo" if fifo else base
    create_attrs = dict(attrs)
    if fifo:
        create_attrs["FifoQueue"] = "true"
    url = sqs.create_queue(
        QueueName=name, Attributes=create_attrs, tags=dict(_MANAGED)
    )["QueueUrl"]
    ctx.on_cleanup(lambda: ctx.client("sqs").delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return {"name": name, "url": url, "arn": arn}


def _sqs_read_statements(source_arn: str) -> list[dict[str, Any]]:
    return [
        {
            "Effect": "Allow",
            "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
            "Resource": source_arn,
        }
    ]


def _create_pipe_role(ctx, statements: list[dict[str, Any]]) -> dict[str, str]:
    """Create the pipe execution role (trusts pipes.amazonaws.com) carrying one inline policy."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, "role")
    policy_name = "pipe-inline"
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "pipes.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    _put_role_policy(ctx, role_name, policy_name, statements)
    return {"name": role_name, "arn": arn, "policy": policy_name}


def _put_role_policy(
    ctx, role_name: str, policy_name: str, statements: list[dict[str, Any]]
) -> None:
    ctx.client("iam").put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )


def _delete_role(ctx, role_name: str) -> None:
    """Teardown: an IAM role cannot be deleted while it still holds inline policies."""
    iam = ctx.client("iam")
    for pname in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    iam.delete_role(RoleName=role_name)


def _create_pipe(
    ctx,
    *,
    source: str,
    target: str,
    role_arn: str,
    wait_for: str = "RUNNING",
    timeout_s: float = 300.0,
    **extra: Any,
) -> str:
    """Create a pipe, wait for CurrentState == wait_for, and return its name.

    Retries only the assume-role/PassRole errors a freshly created role hits during IAM propagation.
    """
    pipes = ctx.client("pipes")
    name = _xname(ctx, "pipe")
    last: ClientError | None = None
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else min(60.0, left))
    while time.monotonic() < deadline:
        try:
            pipes.create_pipe(
                Name=name,
                RoleArn=role_arn,
                Source=source,
                Target=target,
                DesiredState="RUNNING",
                Tags=dict(_MANAGED),
                **extra,
            )
            break
        except ClientError as exc:
            text = str(exc)
            if "cannot be assumed" in text or "iam:PassRole" in text:
                last = exc
                time.sleep(2)
                continue
            raise
    else:
        raise AssertionError(
            f"pipe {name!r} could not be created: EventBridge Pipes never managed to assume the "
            f"freshly created execution role {role_arn!r} within 60 s. Last error: {last!r}"
        )
    ctx.on_cleanup(lambda: _delete_pipe(ctx, name))
    _poll_until(
        lambda: pipes.describe_pipe(Name=name)["CurrentState"],
        lambda s: s == wait_for,
        timeout_s=timeout_s,
        interval_s=5.0,
        description=(
            f"pipe {name!r} reaching CurrentState=={wait_for!r} after CreatePipe (a pipe that "
            f"parks in CREATING or reaches CREATE_FAILED never polls its source)"
        ),
    )
    return name


def _delete_pipe(ctx, name: str) -> None:
    """Teardown: DeletePipe is refused with ConflictException while the pipe is transitioning."""
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + 45.0
    while True:
        try:
            pipes.delete_pipe(Name=name)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException":
                raise
            if time.monotonic() > deadline:
                raise
            time.sleep(5)


def _receive(ctx, queue_url: str, *, attribute_names: list[str] | None = None) -> list[dict]:
    """One bounded long-poll receive; deletes what it takes so nothing is counted twice."""
    sqs = ctx.client("sqs")
    kwargs: dict[str, Any] = {
        "QueueUrl": queue_url,
        "MaxNumberOfMessages": 10,
        "WaitTimeSeconds": 5,
    }
    if attribute_names is not None:
        # AttributeNames (not MessageSystemAttributeNames) so this works on older botocore.
        kwargs["AttributeNames"] = attribute_names
    resp = sqs.receive_message(**kwargs)
    # SQS omits "Messages" entirely on an empty receive.
    msgs = resp["Messages"] if "Messages" in resp else []
    out = []
    for msg in msgs:
        out.append(msg)
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _drain(ctx, queue_url: str, *, window_s: float) -> list[dict]:
    """Receive and delete everything that shows up on a queue inside a bounded window."""
    got: list[dict] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        got.extend(_receive(ctx, queue_url))
    return got


def _await_marker(
    ctx, queue_url: str, marker: str, *, timeout_s: float, description: str
) -> tuple[list[dict], float]:
    """Long-poll a queue until a message body containing `marker` arrives.

    Returns (everything received while waiting, seconds elapsed); the latency sizes absence windows.
    """
    started = time.monotonic()
    got: list[dict] = []

    def _pull() -> list[dict]:
        got.extend(_receive(ctx, queue_url))
        return got

    _poll_until(
        _pull,
        lambda msgs: any(marker in m["Body"] for m in msgs),
        timeout_s=timeout_s,
        interval_s=0.0,
        description=description,
    )
    return got, time.monotonic() - started


def _await_probe(ctx, queue_url: str, send, *, timeout_s: float, description: str) -> float:
    """Send a probe via send(n), and a fresh one every 30 s, until one reaches queue_url.

    A poller still on the old filter consumes and drops a probe, so one probe alone can be lost.
    Returns the seconds since the first probe was sent.
    """
    started = time.monotonic()
    sent: list[str] = []
    got: list[dict] = []
    while True:
        if len(sent) <= (time.monotonic() - started) // 30.0:
            sent.append(send(len(sent)))
        got.extend(_receive(ctx, queue_url))
        if any(marker in m["Body"] for marker in sent for m in got):
            return time.monotonic() - started
        if time.monotonic() - started >= timeout_s:
            raise AssertionError(
                f"{description}: not satisfied within {timeout_s}s after {len(sent)} probe(s). "
                f"Last observed value: {[m['Body'] for m in got]!r}"
            )


def _outstanding(ctx, queue_url: str) -> int:
    """Messages the source queue still owns: visible plus in flight."""
    attrs = ctx.client("sqs").get_queue_attributes(
        QueueUrl=queue_url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    return int(attrs["ApproximateNumberOfMessages"]) + int(
        attrs["ApproximateNumberOfMessagesNotVisible"]
    )


def _await_source_fully_processed(ctx, queue_url: str, *, timeout_s: float, why: str) -> None:
    """Wait until the source queue holds nothing, visible or in flight.

    Pipes deletes a processed SQS record, including one the filter dropped, so an empty source
    proves every record has already been filtered and delivered.
    """
    _poll_until(
        lambda: _outstanding(ctx, queue_url),
        lambda n: n == 0,
        timeout_s=timeout_s,
        interval_s=5.0,
        description=(
            f"source queue {queue_url} draining to zero outstanding records ({why}); a non-zero "
            f"residue means the pipe never consumed the records, so no absence claim is possible"
        ),
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
