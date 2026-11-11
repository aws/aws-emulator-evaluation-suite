"""native-log-group-delete-leaves-cloudcontrol-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "native-log-group-delete-leaves-cloudcontrol-not-found"
GROUP = "native-truth"
SERVICES = ["cloudcontrol", "logs"]

LOG_GROUP_TYPE = "AWS::Logs::LogGroup"
RETENTION_DAYS = 1


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A log group created with CloudWatch Logs's own API is visible to Cloud Control with its own
    values, and once Logs itself deletes it Cloud Control GetResource answers
    ResourceNotFoundException with the handler's exact not-found message, not a stale success.

    Reference: https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/resource-operations.html
    """
    cc = ctx.client("cloudcontrol")
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-behav-ccnat-")

    logs.create_log_group(logGroupName=name, tags={"sim2real": CHECK})
    ctx.on_cleanup(_teardown(lambda: logs.delete_log_group(logGroupName=name), "ResourceNotFoundException"))
    logs.put_retention_policy(logGroupName=name, retentionInDays=RETENTION_DAYS)
    native = _poll_until(
        lambda: _describe_group_or_none(logs, name),
        lambda g: g is not None and g.get("retentionInDays") == RETENTION_DAYS,
        timeout_s=30.0,
        interval_s=2.0,
        reason=f"CloudWatch Logs to report the retention policy on {name!r}",
    )

    # ---- Cloud Control resolves a log group it never created, with Logs's own values ------------
    described = _poll_until(
        lambda: _get_resource_or_none(cc, name),
        lambda desc: desc is not None,
        timeout_s=30.0,
        interval_s=2.0,
        reason=f"Cloud Control GetResource to resolve {name!r}, a log group it never created",
    )
    assert described["Identifier"] == name, (
        f"GetResource echoed Identifier {described['Identifier']!r}, expected {name!r}"
    )
    props = json.loads(described["Properties"])
    assert props.get("LogGroupName") == name, (
        f"Cloud Control reports LogGroupName {props.get('LogGroupName')!r}, expected {name!r}"
    )
    assert props.get("RetentionInDays") == RETENTION_DAYS, (
        f"Cloud Control reports RetentionInDays {props.get('RetentionInDays')!r}, Logs reports "
        f"{native['retentionInDays']!r}"
    )
    assert props.get("Arn") == native["arn"], (
        f"Cloud Control reports Arn {props.get('Arn')!r}, Logs reports {native['arn']!r}"
    )

    # ---- ListResources enumerates it, paginated ---------------------------------------------
    _poll_until(
        lambda: _list_all_log_group_names(cc),
        lambda names: name in names,
        timeout_s=30.0,
        interval_s=2.0,
        reason=f"ListResources to enumerate {name!r}, a log group Cloud Control never created",
    )

    # ---- break the one thing: Logs itself deletes the group, not Cloud Control -------------------
    logs.delete_log_group(logGroupName=name)
    _poll_until(
        lambda: _describe_group_or_none(logs, name),
        lambda g: g is None,
        timeout_s=45.0,
        interval_s=2.0,
        reason=f"CloudWatch Logs to report {name!r} gone after its own DeleteLogGroup",
    )

    # ---- the effect: Cloud Control must stop vouching for a log group Logs has deleted ---------
    cc_error = _poll_for_client_error(
        lambda: cc.get_resource(TypeName=LOG_GROUP_TYPE, Identifier=name),
        timeout_s=45.0,
        interval_s=2.0,
        reason=f"Cloud Control GetResource to report {name!r} gone after the native delete",
    )
    compound_identifier = json.dumps(
        {"/properties/LogGroupName": name}, separators=(",", ":")
    )
    expected_message = _handler_not_found(
        cc_error[1],
        f"AWS::Logs::LogGroup Handler returned status FAILED: Resource of type "
        f"'AWS::Logs::LogGroup' with identifier '{compound_identifier}' was not found.",
    )
    assert cc_error == ("ResourceNotFoundException", expected_message), (
        f"GetResource for the natively-deleted log group {name!r} answered {cc_error!r}, expected "
        f"('ResourceNotFoundException', {expected_message!r}); a target that still serves it is "
        f"over-permissive"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s, reason):
    """Bounded retry with a deadline and a stated reason. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"waited {timeout_s}s for {reason} and it never happened; last observation {last!r}"
    )


def _describe_group_or_none(logs, name):
    groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
    for g in groups:
        if g["logGroupName"] == name:
            return g
    return None


def _get_resource_or_none(cc, name):
    try:
        return cc.get_resource(TypeName=LOG_GROUP_TYPE, Identifier=name)["ResourceDescription"]
    except ClientError:
        return None


def _list_all_log_group_names(cc):
    """Every identifier ListResources reports for AWS::Logs::LogGroup, across pages."""
    found: set[str] = set()
    kwargs = {"TypeName": LOG_GROUP_TYPE}
    for _ in range(500):
        resp = cc.list_resources(**kwargs)
        found.update(d["Identifier"] for d in resp.get("ResourceDescriptions", []))
        token = resp.get("NextToken")
        if not token:
            return found
        kwargs["NextToken"] = token
    raise AssertionError(
        f"ListResources for {LOG_GROUP_TYPE} still returned a NextToken after 500 pages "
        f"({len(found)} identifiers); pagination is not terminating"
    )


def _poll_for_client_error(fn, *, timeout_s, interval_s, reason):
    """Poll fn() until it raises ClientError and return its (Error.Code, Error.Message). RAISES
    when fn() is still succeeding at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"waited {timeout_s}s for {reason} and it never happened; last result {result!r}"
            )
        time.sleep(interval_s)


def _handler_not_found(message, detail):
    """Whether message is the handler's NotFound refusal; its trailing RequestToken is server-chosen."""
    token = message.rpartition("RequestToken: ")[2].removesuffix(")")
    return f"{detail} (HandlerErrorCode: NotFound, RequestToken: {token})"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
