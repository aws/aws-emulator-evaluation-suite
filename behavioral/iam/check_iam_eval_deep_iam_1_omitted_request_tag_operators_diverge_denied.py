"""iam-eval-deep-iam-1-omitted-request-tag-operators-diverge-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-eval-deep-iam-1-omitted-request-tag-operators-diverge-denied"
GROUP = 'policy_condition_missing_key_denied'
SERVICES = ['iam']

_POLICY = "sim2real-behav-omitted-key"
_PROPAGATION = frozenset({"InvalidClientTokenId", "SignatureDoesNotMatch"})
_ALLOWED, _DENIED = "allowed", "denied"
# operator label -> (condition block over aws:RequestTag/env)
_OPERATORS = {
    "StringEquals": {"StringEquals": {"aws:RequestTag/env": "prod"}},
    "StringEqualsIfExists": {"StringEqualsIfExists": {"aws:RequestTag/env": "prod"}},
    "Null": {"Null": {"aws:RequestTag/env": "true"}},
}
# probe label -> tags sent on TagUser. "omitted" never carries an env key at all.
_PROBES = {
    "omitted": {"tier": "gold"},
    "present-match": {"env": "prod"},
    "present-mismatch": {"env": "dev"},
}
# Outcome vectors (omitted, present-match, present-mismatch): a missing key never equals,
# IfExists skips the test, and Null:true asserts the key is absent.
_EXPECTED = {
    "StringEquals": (_DENIED, _ALLOWED, _DENIED),
    "StringEqualsIfExists": (_ALLOWED, _ALLOWED, _DENIED),
    "Null": (_ALLOWED, _DENIED, _DENIED),
}


def _outcome(fn, settle_s=60):
    """("OK", None) on success, else (error code, error message).

    Only credential-propagation codes are retried (bounded): a fresh key flickers
    InvalidClientTokenId across IAM replicas. Every other code is returned on first sight.
    """
    deadline = time.monotonic() + settle_s
    while True:
        try:
            fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") in _PROPAGATION and time.monotonic() < deadline:
                time.sleep(2)
                continue
            return err.get("Code"), err.get("Message", "")
        return "OK", None


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


def _streak_ok(call, *, n=3, timeout_s=120, description):
    """Poll until `call` (an _outcome thunk) succeeds `n` times IN A ROW. Measured on real IAM:
    a first success can be followed by a stale replica refusing the same grant, so one success
    is not a propagation barrier."""
    run = {"n": 0}

    def step():
        run["n"] = run["n"] + 1 if call() == ("OK", None) else 0
        return run["n"]

    return _poll(step, lambda k: k >= n, timeout_s=timeout_s, interval_s=2,
                 description=description)


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


def _tags_of(client, user, settle_s=60):
    """The user's full tag map (paginated); only credential-propagation codes are retried."""
    deadline = time.monotonic() + settle_s
    while True:
        try:
            out = {}
            for page in client.get_paginator("list_user_tags").paginate(UserName=user):
                for t in page["Tags"]:
                    out[t["Key"]] = t["Value"]
            return out
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _PROPAGATION \
                    or time.monotonic() >= deadline:
                raise
            time.sleep(2)


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """StringEquals, StringEqualsIfExists and Null on aws:RequestTag/env give pairwise distinct
    TagUser verdicts over (env omitted, env=prod, env=dev); an omitted key denies only StringEquals,
    and every denied call is shown via ListUserTags to have applied nothing.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
    """
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    targets = {}
    for op in _OPERATORS:
        name = ctx.unique_name("sim2real-behav-omit-tgt-")
        iam.create_user(UserName=name)
        ctx.on_cleanup(lambda n=name: iam.delete_user(UserName=n))
        targets[op] = name
    arn = {op: f"arn:aws:iam::{account}:user/{n}" for op, n in targets.items()}

    caller = ctx.unique_name("sim2real-behav-omit-caller-")
    iam.create_user(UserName=caller, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=caller))
    caller_arn = f"arn:aws:iam::{account}:user/{caller}"

    statements = [
        {"Sid": f"Tag{op.replace('If', '')}", "Effect": "Allow", "Action": "iam:TagUser",
         "Resource": arn[op], "Condition": cond}
        for op, cond in _OPERATORS.items()
    ]
    statements.append({"Sid": "ReadBack", "Effect": "Allow", "Action": "iam:ListUserTags",
                       "Resource": list(arn.values())})
    iam.put_user_policy(UserName=caller, PolicyName=_POLICY, PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": statements}))
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=caller, PolicyName=_POLICY))

    key = iam.create_access_key(UserName=caller)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=caller, AccessKeyId=key["AccessKeyId"]))
    me = ctx.client("iam", creds={"aws_access_key_id": key["AccessKeyId"],
                                  "aws_secret_access_key": key["SecretAccessKey"]})

    # Propagation barrier from the same document: the unconditioned read-back on every target.
    for op in _OPERATORS:
        _streak_ok(lambda t=targets[op]: _outcome(lambda: _tags_of(me, t)),
                   description=f"the minted user's ListUserTags grant on the {op} target "
                               f"is effective")

    observed = {}
    for op, target in targets.items():
        vector = []
        applied = {}
        for probe, kv in _PROBES.items():
            want = _EXPECTED[op][len(vector)]
            got = _outcome(lambda kv=kv: me.tag_user(
                UserName=target, Tags=[{"Key": k, "Value": v} for k, v in kv.items()]))
            if got == ("OK", None):
                vector.append(_ALLOWED)
                applied.update(kv)
                _poll(lambda: _tags_of(me, target), lambda t, a=dict(applied): t == a,
                      timeout_s=30, interval_s=2,
                      description=f"{op}/{probe}: the allowed TagUser is visible via ListUserTags")
            else:
                vector.append(_DENIED)
                code, message = got
                assert code == "AccessDenied", (
                    f"{op}/{probe}: a refused TagUser must be exactly AccessDenied; got {got!r}"
                )
                expected = _with_authorization_details(
                    f"User: {caller_arn} is not authorized to perform: iam:TagUser on resource: "
                    f"user {target} because no identity-based policy allows the iam:TagUser action",
                    message,
                )
                assert message == expected, (
                    f"{op}/{probe}: denial must be for lack of an applicable allow; got {message!r}"
                )
                now = _tags_of(me, target)
                assert now == applied, (
                    f"{op}/{probe}: a denied TagUser must apply nothing; expected {applied!r}, "
                    f"ListUserTags shows {now!r}"
                )
            assert vector[-1] == want, (
                f"{op} with the {probe!r} probe ({kv!r}) must be {want}; it was {vector[-1]} "
                f"({got!r})"
            )
        observed[op] = tuple(vector)

    # The omitted-key case alone separates StringEquals from both others...
    omitted = {op: v[0] for op, v in observed.items()}
    assert omitted["StringEquals"] == _DENIED and omitted["StringEqualsIfExists"] == _ALLOWED \
        and omitted["Null"] == _ALLOWED, f"omitted-key outcomes diverged wrongly: {omitted!r}"
    # ...and across all three probes the three operators are pairwise distinct.
    assert len(set(observed.values())) == 3, (
        f"the three operators' outcome vectors must be pairwise distinct; got {observed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
