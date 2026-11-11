"""resource-level-arn-scoping-enforced-on-a-real-call."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-level-arn-scoping-enforced-on-a-real-call"
GROUP = 'policy_simulation'
SERVICES = ['iam']

_SCOPED = "sim2real-behav-arnscope-one-target"


def _budget_s(ctx, cap_s):
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


def _error(fn):
    """The captured AWS (code, message); a successful call is a failure of the refusal claim."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call succeeded where AWS refuses it")


def _client_for_credentials(ctx, access_key_id, secret_access_key, service="iam"):
    """A client signing AS the minted principal, not ``ctx``'s own execution role."""
    return ctx.client(service, creds={"aws_access_key_id": access_key_id,
                                      "aws_secret_access_key": secret_access_key})


# IAM's console host for authorization details is fixed to its global partition region.
_DETAILS_URL = "https://us-east-1.console.aws.amazon.com/iam/home?region=us-east-1#/authorization-details/"


def _denial_message(principal_arn, action, resource, why, message, *, details):
    """The exact AccessDenied message AWS writes for this principal, action and resource.

    ``why`` is the policy type AWS names (``identity-based``, ``session``). With ``details``, AWS
    appends a per-request authorization id, read back from the message and placed twice.
    """
    base = (
        f"User: {principal_arn} is not authorized to perform: {action} on resource: {resource} "
        f"because no {why} policy allows the {action} action"
    )
    if not details:
        return base
    auth = (message or "").rsplit(" ", 1)[-1]
    return (
        f"{base}. Go to {_DETAILS_URL}{auth} for complete details, or call the "
        f"GetRequestAuthorizationDetails API with the following authorization id: {auth}"
    )


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not reached within {timeout_s}s; last observation {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


def _try_get_user(client, user_name):
    """(code_or_OK, returned_user_name_or_None) -- one probe, two observations."""
    try:
        return "OK", client.get_user(UserName=user_name)["User"]["UserName"]
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), None


def _decision(iam, source_arn, action, resource_arn):
    results = iam.simulate_principal_policy(
        PolicySourceArn=source_arn, ActionNames=[action], ResourceArns=[resource_arn]
    )["EvaluationResults"]
    return results[0]["EvalDecision"]


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c7")
def run(ctx) -> None:
    """A policy whose Resource names one user ARN, with no wildcard, allows a real signed call on
    that user and refuses the same call on a sibling with AccessDenied and the exact message,
    matching the simulator's allowed and implicitDeny decisions."""
    iam = ctx.client("iam")
    caller = ctx.unique_name("sim2real-behav-arnscope-caller-")
    target_in = ctx.unique_name("sim2real-behav-arnscope-in-")
    target_out = ctx.unique_name("sim2real-behav-arnscope-out-")

    _tag = [{"Key": "sim2real", "Value": CHECK}]

    iam.create_user(UserName=caller, Path="/", Tags=_tag)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=caller))
    caller_arn = iam.get_user(UserName=caller)["User"]["Arn"]

    iam.create_user(UserName=target_in, Path="/", Tags=_tag)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=target_in))
    target_in_arn = iam.get_user(UserName=target_in)["User"]["Arn"]

    iam.create_user(UserName=target_out, Path="/", Tags=_tag)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=target_out))
    target_out_arn = iam.get_user(UserName=target_out)["User"]["Arn"]

    # Resource is exactly ONE user ARN. No "*" appears anywhere in this document.
    document = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "iam:GetUser", "Resource": target_in_arn}],
    })
    assert "*" not in document, (
        f"the whole claim is wildcard-free scoping, so the document must contain no '*': {document!r}"
    )
    iam.put_user_policy(UserName=caller, PolicyName=_SCOPED, PolicyDocument=document)
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=caller, PolicyName=_SCOPED))

    key = iam.create_access_key(UserName=caller)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=caller, AccessKeyId=key["AccessKeyId"])
    )
    as_caller = _client_for_credentials(ctx, key["AccessKeyId"], key["SecretAccessKey"])

    # --- Positive control: the in-scope target. Poll past credential replication only.
    allowed = _poll(
        lambda: _try_get_user(as_caller, target_in),
        lambda r: r[0] == "OK",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the scoped grant becomes effective for the in-scope target on a real call",
    )
    assert allowed[0] == "OK", (
        f"the policy names {target_in!r}'s ARN as the Resource, so the real signed GetUser against "
        f"it must succeed; got {allowed[0]!r}"
    )
    assert allowed[1] == target_in, (
        f"the call must have returned the TARGET, not the caller: expected {target_in!r}, got "
        f"{allowed[1]!r} -- an emulator echoing the caller's own identity fails here"
    )

    # --- Break exactly one thing: the same call, same principal, a sibling target ARN.
    denied, message = _error(lambda: as_caller.get_user(UserName=target_out))
    assert denied == "AccessDenied", (
        f"{target_out!r} is not the Resource the policy names, so the identical real signed call "
        f"must be refused with exactly AccessDenied; got {denied!r}"
    )
    want = _denial_message(caller_arn, "iam:GetUser", f"user {target_out}", "identity-based",
                           message, details=True)
    assert message == want, f"AccessDenied message: expected {want!r}, got {message!r}"

    # --- The simulator must agree with the enforcement path on BOTH resource ARNs.
    out_decision = _decision(iam, caller_arn, "iam:GetUser", target_out_arn)
    assert out_decision == "implicitDeny", (
        f"the out-of-scope resource ARN is covered by no statement, so the simulator must say "
        f"'implicitDeny'; got {out_decision!r}"
    )
    in_decision = _decision(iam, caller_arn, "iam:GetUser", target_in_arn)
    assert in_decision == "allowed", (
        f"the in-scope resource ARN is named by the statement, so the simulator must say 'allowed', "
        f"agreeing with the real call that already succeeded; got {in_decision!r}"
    )

    # --- The in-scope target still works after the denial, so nothing above was drift. Bounded
    #     poll, not a single shot: IAM replicates a grant per-replica, so the SAME call can succeed
    #     and then transiently 403 while convergence finishes, with the grant unchanged.
    again = _poll(
        lambda: _try_get_user(as_caller, target_in),
        lambda r: r[0] == "OK",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="the in-scope target still resolves after the out-of-scope denial",
    )
    assert again[0] == "OK", (
        f"the in-scope target must still succeed after the out-of-scope denial; got {again[0]!r} -- "
        f"a denial that poisons the principal is not resource scoping"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
