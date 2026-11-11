"""policy-variable-username-scopes-one-shared-policy-per-caller."""
from __future__ import annotations

import json
import time
import urllib.parse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "policy-variable-username-scopes-one-shared-policy-per-caller"
GROUP = "policy_lifecycle"
SERVICES = ["iam"]

_VARIABLE = "${aws:username}"
_ESCALATION = "sim2real-behav-var-explicit-cross-user"
_MARK = [{"Key": "sim2real", "Value": CHECK}]


def _budget_s(ctx, cap_s):
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """One managed policy on `user/${aws:username}`, attached to two users, lets each list its own
    access keys and refuses each the other's with AccessDenied; the stored document keeps the
    literal variable, and an explicit cross-user grant lifts the refusal until it is deleted.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html
    """
    iam = ctx.client("iam")

    first = ctx.unique_name("sim2real-pvar-a-")
    iam.create_user(UserName=first, Path="/", Tags=_MARK)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=first))
    first_arn = iam.get_user(UserName=first)["User"]["Arn"]
    account = first_arn.split(":")[4]

    second = ctx.unique_name("sim2real-pvar-b-")
    iam.create_user(UserName=second, Path="/", Tags=_MARK)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=second))
    second_arn = iam.get_user(UserName=second)["User"]["Arn"]

    # ONE document, no wildcard, no user name in it -- only the variable. Region is absent from an
    # iam ARN by construction; the account comes from an ARN the target itself minted.
    document = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "SelfServiceOnly",
            "Effect": "Allow",
            "Action": ["iam:ListAccessKeys", "iam:ListUserTags"],
            "Resource": f"arn:aws:iam::{account}:user/{_VARIABLE}",
        }],
    }
    policy = iam.create_policy(
        PolicyName=ctx.unique_name("sim2real-pvar-shared-"),
        PolicyDocument=json.dumps(document),
        Description=f"sim2real {CHECK}",
        Tags=_MARK,
    )["Policy"]
    policy_arn = policy["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=policy_arn))

    # --- The variable is STORED, not resolved at write time. Read back through a different
    #     operation than the one that wrote it.
    stored = _default_version_document(iam, policy_arn)
    stored_resource = stored["Statement"][0]["Resource"]
    assert stored_resource == f"arn:aws:iam::{account}:user/{_VARIABLE}", (
        f"the stored default policy version must still contain the literal variable "
        f"{_VARIABLE!r} -- expansion belongs to evaluation time, not to CreatePolicy; expected "
        f"'arn:aws:iam::{account}:user/{_VARIABLE}', GetPolicyVersion returned {stored_resource!r}"
    )
    assert first not in json.dumps(stored) and second not in json.dumps(stored), (
        f"neither user name may appear in the stored document -- if it does, the target resolved the "
        f"variable at write time and cannot be serving two callers from one policy; the document is "
        f"{stored!r}"
    )

    signer = {}
    for name in (first, second):
        iam.attach_user_policy(UserName=name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda n=name: iam.detach_user_policy(UserName=n, PolicyArn=policy_arn))
        key = iam.create_access_key(UserName=name)["AccessKey"]
        ctx.on_cleanup(lambda n=name, k=key: iam.delete_access_key(
            UserName=n, AccessKeyId=k["AccessKeyId"]
        ))
        signer[name] = _signing_as(ctx, "iam", key)

    # --- Both users hold the SAME policy ARN. Asserted before any conclusion is drawn from an
    #     authorization outcome, so an unattached policy can never read as a working variable.
    for name in (first, second):
        attached = [
            p["PolicyArn"]
            for page in iam.get_paginator("list_attached_user_policies").paginate(UserName=name)
            for p in page["AttachedPolicies"]
        ]
        assert attached == [policy_arn], (
            f"{name!r} must hold exactly the one shared policy and nothing else, or a success below "
            f"could come from a different grant; expected [{policy_arn!r}], the paginated "
            f"ListAttachedUserPolicies reports {attached!r}"
        )
        inline = [
            n
            for page in iam.get_paginator("list_user_policies").paginate(UserName=name)
            for n in page["PolicyNames"]
        ]
        assert inline == [], (
            f"{name!r} must hold no inline policy at this point, so the shared managed policy is "
            f"the only possible source of a grant; ListUserPolicies reports {inline!r}"
        )

    # --- Twin positive controls, one per caller: the same document expands differently for each.
    for name in (first, second):
        self_read = _poll(
            lambda n=name: _outcome(lambda: signer[n].list_access_keys(UserName=n)),
            lambda o: o == "OK",
            timeout_s=_budget_s(ctx, 90.0),
            interval_s=3,
            description=f"the shared policy's {_VARIABLE} expands to {name!r} and permits its own read",
        )
        assert self_read == "OK", (
            f"{_VARIABLE} must expand to {name!r}, so that user's real signed ListAccessKeys on "
            f"ITSELF must succeed; expected 'OK', got {self_read!r} -- an emulator that string-"
            f"compares the ARN literally denies this"
        )

    # --- The negatives, in the same instant, symmetric. Nothing changed between these and the
    #     successes above except which name the request addresses.
    cross = {
        (first, second): _rejected(lambda: signer[first].list_access_keys(UserName=second)),
        (second, first): _rejected(lambda: signer[second].list_access_keys(UserName=first)),
    }
    caller_arns = {first: first_arn, second: second_arn}

    def no_allow(caller, target):
        return (
            f"User: {caller_arns[caller]} is not authorized to perform: iam:ListAccessKeys on "
            f"resource: user {target} because no identity-based policy allows the "
            "iam:ListAccessKeys action"
        )

    for (caller, target), (code, message) in cross.items():
        assert code == "AccessDenied", (
            f"{_VARIABLE} expands to {caller!r}, so the shared policy grants nothing on {target!r} "
            f"and the real signed call must be refused with exactly AccessDenied; got {code!r} -- an "
            f"emulator that treats the variable as a wildcard over-permits here, and the symmetry of "
            f"the two refusals rules out 'this one user happens to be denied everything'"
        )
        expected = _with_authorization_details(no_allow(caller, target), message)
        assert message == expected, f"expected message {expected!r}, got {message!r}"

    # --- Restore: an EXPLICIT cross-user grant makes the refused call work, proving the refusal was
    #     the variable's scoping and not a blanket ban on reading another user.
    iam.put_user_policy(
        UserName=first,
        PolicyName=_ESCALATION,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "iam:ListAccessKeys",
                "Resource": second_arn,
            }],
        }),
    )
    ctx.on_cleanup(lambda: _drop_user_policy(iam, first, _ESCALATION))
    widened = _poll(
        lambda: _outcome(lambda: signer[first].list_access_keys(UserName=second)),
        lambda o: o == "OK",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="an explicit cross-user grant makes the previously refused read succeed",
    )
    assert widened == "OK", (
        f"with {second_arn!r} named explicitly in an inline policy, {first!r}'s real signed call "
        f"must succeed -- so the earlier AccessDenied was the variable's scoping, not a refusal of "
        f"cross-user reads in general; expected 'OK', got {widened!r}"
    )

    # --- And removing it puts the boundary back.
    iam.delete_user_policy(UserName=first, PolicyName=_ESCALATION)
    narrowed_code, narrowed_message = _poll(
        lambda: _outcome_and_message(lambda: signer[first].list_access_keys(UserName=second)),
        lambda o: o[0] == "AccessDenied",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=3,
        description="removing the explicit grant restores the variable-scoped refusal",
    )
    assert narrowed_code == "AccessDenied", (
        f"once the explicit grant is deleted, only the {_VARIABLE} policy remains and the "
        f"cross-user read must be refused with exactly AccessDenied again; got {narrowed_code!r}"
    )
    expected = _with_authorization_details(no_allow(first, second), narrowed_message)
    assert narrowed_message == expected, f"expected message {expected!r}, got {narrowed_message!r}"


def _outcome(fn):
    """``"OK"`` on success, else the AWS error code; callers poll it or assert an exact value."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code") or "NO_ERROR_CODE"
    return "OK"


def _outcome_and_message(fn):
    """``("OK", None)`` on success, else the AWS error ``(code, message)``."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code") or "NO_ERROR_CODE", err.get("Message")
    return "OK", None


def _rejected(fn):
    """``(code, message)`` of a call real AWS MUST refuse; an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code") or "NO_ERROR_CODE", err.get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _with_authorization_details(base, message):
    """IAM's access-denied text: ``base`` followed by a pointer to the per-request authorization
    id, the one opaque token read back from the message; the console link names us-east-1."""
    region = "us-east-1"
    marker = "authorization id: "
    auth_id = message.rsplit(marker, 1)[-1] if message and marker in message else "<absent>"
    return (
        f"{base}. Go to https://{region}.console.aws.amazon.com/iam/home?region={region}"
        f"#/authorization-details/{auth_id} for complete details, or call the "
        f"GetRequestAuthorizationDetails API with the following authorization id: {auth_id}"
    )


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    """Bounded retry with a deadline; raises on timeout. New keys and attachments propagate
    asynchronously and no API reports them effective."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} did not happen within {timeout_s}s; last observation {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


def _signing_as(ctx, service, key):
    """A client for ``service`` signing as the owner of ``key``, on this ctx's endpoint."""
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": key["AccessKeyId"],
            "aws_secret_access_key": key["SecretAccessKey"],
        },
    )


def _default_version_document(iam, policy_arn):
    """The default version's document as a dict, via GetPolicy + GetPolicyVersion. The extra
    unquote is idempotent if botocore already URL-decoded the document."""
    default = iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
    doc = iam.get_policy_version(PolicyArn=policy_arn, VersionId=default)["PolicyVersion"][
        "Document"
    ]
    if isinstance(doc, str):
        return json.loads(urllib.parse.unquote(doc))
    return doc


def _drop_user_policy(iam, user, policy_name):
    """Teardown-only: tolerate the inline policy already being deleted by the body."""
    try:
        iam.delete_user_policy(UserName=user, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
