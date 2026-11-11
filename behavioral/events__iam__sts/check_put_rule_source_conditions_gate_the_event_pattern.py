"""put-rule-source-conditions-gate-the-event-pattern."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-rule-source-conditions-gate-the-event-pattern"
GROUP = "enforcement"
SERVICES = ["events", "iam", "sts"]

_SESSION = "sim2real-behav"
# A session token AssumeRole just minted can be refused for a few seconds.
_TOKEN_NOT_YET_VALID = ("UnrecognizedClientException", "The security token included in the request is invalid.")


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A Null events:source condition on PutRule refuses a pattern with no source field and
    admits one that has it; a ForAllValues:StringEquals condition further limits that source.
    """
    events = ctx.client("events")
    iam = ctx.client("iam")

    bus = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))

    null_role, null_role_arn = _role(ctx, iam, {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Action": "events:PutRule", "Resource": "*",
            "Condition": {"Null": {"events:source": "false"}},
        }],
    })
    null_client = ctx.client("events", creds=_assume(ctx, null_role_arn))

    # --- the Null condition admits a pattern that has a source, proving the policy is in force. ---
    sourced_rule = ctx.unique_name("sim2real-behav-rule-")
    ctx.on_cleanup(lambda: events.delete_rule(Name=sourced_rule, EventBusName=bus))
    source = ctx.unique_name("sim2real.")
    _until_admitted(lambda: null_client.put_rule(
        Name=sourced_rule, EventBusName=bus, EventPattern=json.dumps({"source": [source]}),
    ), _denied(ctx, null_role, bus, sourced_rule))
    described = events.describe_rule(Name=sourced_rule, EventBusName=bus)
    assert json.loads(described["EventPattern"]) == {"source": [source]}, (
        f"the admitted rule's pattern was {described['EventPattern']!r}"
    )

    # --- the same condition refuses a pattern that has no source field, and nothing is created. ---
    sourceless_rule = ctx.unique_name("sim2real-behav-rule-")
    ctx.on_cleanup(lambda: _delete_rule_if_present(events, sourceless_rule, bus))
    _NO_SOURCE_DENIED = _denied(ctx, null_role, bus, sourceless_rule)
    code, message = _error(lambda: null_client.put_rule(
        Name=sourceless_rule, EventBusName=bus,
        EventPattern=json.dumps({"detail-type": ["sim2real.detail"]}),
    ))
    assert (code, message) == _NO_SOURCE_DENIED, f"the sourceless PutRule gave {code!r} {message!r}"
    absent_code, absent_message = _error(lambda: events.describe_rule(Name=sourceless_rule, EventBusName=bus))
    assert (absent_code, absent_message) == (
        "ResourceNotFoundException", f"Rule {sourceless_rule} does not exist on EventBus {bus}.",
    ), f"the refused PutRule must create no rule; DescribeRule gave {absent_code!r} {absent_message!r}"

    # --- a ForAllValues:StringEquals condition restricts PutRule to that one source value. ---
    allowed_source = ctx.unique_name("sim2real.")
    other_source = ctx.unique_name("sim2real.")
    eq_role, eq_role_arn = _role(ctx, iam, {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Action": "events:PutRule", "Resource": "*",
            "Condition": {"ForAllValues:StringEquals": {"events:source": allowed_source}},
        }],
    })
    eq_client = ctx.client("events", creds=_assume(ctx, eq_role_arn))

    eq_rule = ctx.unique_name("sim2real-behav-rule-")
    ctx.on_cleanup(lambda: events.delete_rule(Name=eq_rule, EventBusName=bus))
    _until_admitted(lambda: eq_client.put_rule(
        Name=eq_rule, EventBusName=bus, EventPattern=json.dumps({"source": [allowed_source]}),
    ), _denied(ctx, eq_role, bus, eq_rule))
    described = events.describe_rule(Name=eq_rule, EventBusName=bus)
    assert json.loads(described["EventPattern"]) == {"source": [allowed_source]}, (
        f"the allowed-source rule's pattern was {described['EventPattern']!r}"
    )

    other_rule = ctx.unique_name("sim2real-behav-rule-")
    ctx.on_cleanup(lambda: _delete_rule_if_present(events, other_rule, bus))
    _OTHER_SOURCE_DENIED = _denied(ctx, eq_role, bus, other_rule)
    code, message = _error(lambda: eq_client.put_rule(
        Name=other_rule, EventBusName=bus, EventPattern=json.dumps({"source": [other_source]}),
    ))
    assert (code, message) == _OTHER_SOURCE_DENIED, f"the other-source PutRule gave {code!r} {message!r}"
    absent_code, absent_message = _error(lambda: events.describe_rule(Name=other_rule, EventBusName=bus))
    assert (absent_code, absent_message) == (
        "ResourceNotFoundException", f"Rule {other_rule} does not exist on EventBus {bus}.",
    ), f"the refused PutRule must create no rule; DescribeRule gave {absent_code!r} {absent_message!r}"


def _denied(ctx, role: str, bus: str, rule: str) -> tuple[str, str]:
    """The (code, message) PutRule of ``rule`` on ``bus`` is refused with for the role's session."""
    return (
        "AccessDeniedException",
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role}/{_SESSION} is not authorized "
        f"to perform: events:PutRule on resource: "
        f"arn:aws:events:{ctx.region}:{ctx.account}:rule/{bus}/{rule} because no "
        "identity-based policy allows the events:PutRule action",
    )


def _role(ctx, iam, policy: dict) -> tuple[str, str]:
    """A role the account may assume, carrying exactly ``policy`` as its one inline policy."""
    name = ctx.unique_name("sim2real-behav-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
        "Action": "sts:AssumeRole",
    }]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(RoleName=name, PolicyName="scoped", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="scoped"))
    return name, arn


def _assume(ctx, role_arn: str, timeout_s: float = 60.0) -> dict:
    """Credentials for ``role_arn``, retrying only the refusal a not-yet-propagated trust policy gives."""
    sts = ctx.client("sts")
    caller = sts.get_caller_identity()["Arn"]
    unpropagated = (
        "AccessDenied",
        f"User: {caller} is not authorized to perform: sts:AssumeRole on resource: {role_arn}",
    )
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            c = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION)["Credentials"]
            return {"aws_access_key_id": c["AccessKeyId"], "aws_secret_access_key": c["SecretAccessKey"],
                    "aws_session_token": c["SessionToken"]}
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (err.get("Code"), err.get("Message")) != unpropagated or time.monotonic() >= deadline:
                raise
            time.sleep(3)


def _error(fn, timeout_s: float = 60.0) -> tuple[str, str]:
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails.

    A just-minted session token can be refused as unrecognized for a few seconds; that is
    retried, never returned.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (err.get("Code"), err.get("Message")) == _TOKEN_NOT_YET_VALID and time.monotonic() < deadline:
                time.sleep(3)
                continue
            return err.get("Code"), err.get("Message")
        raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _until_admitted(fn, denied: tuple[str, str], timeout_s: float = 90.0):
    """Retry fn() while a just-attached identity policy propagates: only ``denied`` or a
    not-yet-valid session token is retried."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (err.get("Code"), err.get("Message")) not in (denied, _TOKEN_NOT_YET_VALID):
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"the role's identity policy never admitted the call in {timeout_s}s: {exc}"
                ) from exc
            time.sleep(3)


def _delete_rule_if_present(events, name: str, bus: str) -> None:
    """Teardown for a rule a refused PutRule must not have created."""
    try:
        events.describe_rule(Name=name, EventBusName=bus)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    events.delete_rule(Name=name, EventBusName=bus)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
