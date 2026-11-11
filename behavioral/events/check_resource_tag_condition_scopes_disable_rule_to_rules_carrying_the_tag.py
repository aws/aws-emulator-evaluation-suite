"""resource-tag-condition-scopes-disable-rule-to-rules-carrying-the-tag."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-tag-condition-scopes-disable-rule-to-rules-carrying-the-tag"
GROUP = "enforcement"
SERVICES = ["events"]

_SESSION = "sim2real-behav"
_TAG = "sim2real-team"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A role allowed DisableRule only where aws:ResourceTag/sim2real-team is "alpha" disables the
    alpha rule, is denied on the beta rule (which stays ENABLED), and succeeds on it once it is
    retagged alpha: the decision follows the rule's tags.
    """
    events = ctx.client("events")

    bus = ctx.unique_name("sim2real-evb-abac-")
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))

    pattern = json.dumps({"source": [ctx.unique_name("sim2real.abac.")]})
    alpha = ctx.unique_name("sim2real-evb-alpha-")
    events.put_rule(Name=alpha, EventBusName=bus, EventPattern=pattern,
                    Tags=[{"Key": _TAG, "Value": "alpha"}])
    ctx.on_cleanup(lambda: events.delete_rule(Name=alpha, EventBusName=bus))
    beta = ctx.unique_name("sim2real-evb-beta-")
    beta_arn = events.put_rule(Name=beta, EventBusName=bus, EventPattern=pattern,
                               Tags=[{"Key": _TAG, "Value": "beta"}])["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=beta, EventBusName=bus))

    role_name, role_arn = _role(ctx, {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Action": "events:DisableRule", "Resource": "*",
            "Condition": {"StringEquals": {f"aws:ResourceTag/{_TAG}": "alpha"}},
        }],
    })
    scoped = ctx.client("events", creds=_assume(ctx, role_arn))

    _until_allowed(lambda: scoped.disable_rule(Name=alpha, EventBusName=bus), timeout_s=90.0)
    state = events.describe_rule(Name=alpha, EventBusName=bus)["State"]
    assert state == "DISABLED", f"the alpha rule read back {state!r} after the role disabled it"

    code, message = _error(lambda: scoped.disable_rule(Name=beta, EventBusName=bus))
    assert code == "AccessDeniedException", f"DisableRule on the beta-tagged rule gave {code!r}"
    expected = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/{_SESSION} is not authorized "
        f"to perform: events:DisableRule on resource: {beta_arn} because no identity-based policy "
        f"allows the events:DisableRule action"
    )
    assert message == expected, f"DisableRule refusal message was {message!r}"
    state = events.describe_rule(Name=beta, EventBusName=bus)["State"]
    assert state == "ENABLED", f"the refused DisableRule left the beta rule {state!r}"

    events.tag_resource(ResourceARN=beta_arn, Tags=[{"Key": _TAG, "Value": "alpha"}])
    _until_allowed(lambda: scoped.disable_rule(Name=beta, EventBusName=bus), timeout_s=90.0)
    state = events.describe_rule(Name=beta, EventBusName=bus)["State"]
    assert state == "DISABLED", f"after retagging, the beta rule read back {state!r}"



def _error(fn, timeout_s: float = 60.0):
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
            if err.get("Code") == "UnrecognizedClientException" and time.monotonic() < deadline:
                time.sleep(3)
                continue
            return err.get("Code"), err.get("Message")
        raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _until_allowed(fn, timeout_s: float):
    """Retry fn past AccessDeniedException while a just-written policy or tag propagates."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in ("AccessDeniedException", "UnrecognizedClientException"):
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"the call was never allowed: {last}")


def _role(ctx, policy: dict) -> tuple[str, str]:
    """A role the account may assume, carrying exactly ``policy`` as its one inline policy."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-evb-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(RoleName=name, PolicyName="scoped", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="scoped"))
    return name, arn


def _assume(ctx, role_arn: str, timeout_s: float = 60.0) -> dict:
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            c = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION)["Credentials"]
            return {"aws_access_key_id": c["AccessKeyId"], "aws_secret_access_key": c["SecretAccessKey"],
                    "aws_session_token": c["SessionToken"]}
        except ClientError as exc:
            last = exc
            time.sleep(3)
    raise AssertionError(f"could not assume the check's role in {timeout_s}s: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
