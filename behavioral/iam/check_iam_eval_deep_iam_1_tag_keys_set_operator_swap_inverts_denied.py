"""iam-eval-deep-iam-1-tag-keys-set-operator-swap-inverts-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-eval-deep-iam-1-tag-keys-set-operator-swap-inverts-denied"
GROUP = 'policy_condition_set_operators_denied'
SERVICES = ['iam']

_POLICY = "sim2real-behav-setop"
_KEYS = ["env", "tier"]
_PROPAGATION = frozenset({"InvalidClientTokenId", "SignatureDoesNotMatch"})


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


def _await_tags(client, user, expected, what):
    """Bounded read-after-write poll toward the exact expected tag map."""
    return _poll(lambda: _tags_of(client, user), lambda t: t == expected,
                 timeout_s=30, interval_s=2, description=what)


def _doc(operator, target_arn, caller_arn, sentinel_action):
    """The policy under test. `sentinel_action` is granted on the caller itself, unconditioned,
    and differs between the two versions: it is how the swap's propagation is observed without
    reading any outcome the check asserts."""
    cond = {operator: {"aws:TagKeys": _KEYS}}
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "TagUnderTest", "Effect": "Allow", "Action": "iam:TagUser",
             "Resource": target_arn, "Condition": cond},
            {"Sid": "AbsentKeyProbe", "Effect": "Allow", "Action": "iam:GetUser",
             "Resource": target_arn, "Condition": cond},
            {"Sid": "ReadBack", "Effect": "Allow", "Action": "iam:ListUserTags",
             "Resource": target_arn},
            {"Sid": "Sentinel", "Effect": "Allow", "Action": sentinel_action,
             "Resource": caller_arn},
        ],
    })


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


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """Swapping ForAllValues for ForAnyValue on aws:TagKeys [env, tier] inverts {env, owner}
    (denied, then applied) and a key-less GetUser (allowed, then denied); {env}, {env, tier} stay
    allowed and {owner} stays denied, with every TagUser outcome read back via ListUserTags.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-single-vs-multi-valued-context-keys.html
    """
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    target = ctx.unique_name("sim2real-behav-setop-tgt-")
    iam.create_user(UserName=target)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=target))
    target_arn = f"arn:aws:iam::{account}:user/{target}"

    caller = ctx.unique_name("sim2real-behav-setop-caller-")
    iam.create_user(UserName=caller, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=caller))
    caller_arn = f"arn:aws:iam::{account}:user/{caller}"

    iam.put_user_policy(UserName=caller, PolicyName=_POLICY, PolicyDocument=_doc(
        "ForAllValues:StringEquals", target_arn, caller_arn, "iam:ListAttachedUserPolicies"))
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=caller, PolicyName=_POLICY))

    key = iam.create_access_key(UserName=caller)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=caller, AccessKeyId=key["AccessKeyId"]))
    me = ctx.client("iam", creds={"aws_access_key_id": key["AccessKeyId"],
                                  "aws_secret_access_key": key["SecretAccessKey"]})

    def sentinel(action):
        if action == "iam:ListAttachedUserPolicies":
            return _outcome(lambda: me.list_attached_user_policies(UserName=caller))[0]
        return _outcome(lambda: me.list_groups_for_user(UserName=caller))[0]

    def tag(**kv):
        return _outcome(lambda: me.tag_user(
            UserName=target, Tags=[{"Key": k, "Value": v} for k, v in kv.items()]))

    deny_reason = (f"User: {caller_arn} is not authorized to perform: iam:TagUser on resource: "
                   f"user {target} because no identity-based policy allows the iam:TagUser action")

    def assert_denied(outcome, what):
        code, message = outcome
        assert code == "AccessDenied", f"{what} must be AccessDenied; got {outcome!r}"
        expected = _with_authorization_details(deny_reason, message)
        assert message == expected, (
            f"{what} must be refused for lack of an applicable allow ({deny_reason!r}); "
            f"got {message!r}"
        )

    # Propagation barrier: the read-back grant (same document) works as the minted user.
    _streak_ok(lambda: _outcome(lambda: _tags_of(me, target)),
               description="the minted user's ListUserTags grant becomes effective")

    # ---- ForAllValues:StringEquals [env, tier]; over an empty key set ForAllValues is true.
    assert tag(env="a1") == ("OK", None), "ForAllValues: {env} is a subset of {env,tier}"
    _await_tags(me, target, {"env": "a1"}, "after {env:a1} the target carries exactly env=a1")
    assert tag(env="b1", tier="t1") == ("OK", None), "ForAllValues: {env,tier} is a subset"
    after_b = _await_tags(me, target, {"env": "b1", "tier": "t1"},
                          "after {env:b1,tier:t1} the target carries env=b1,tier=t1")
    assert_denied(tag(env="c1", owner="o1"), "ForAllValues: {env,owner} (owner outside the set)")
    after_c = _tags_of(me, target)
    assert "owner" not in after_c, (
        f"a denied TagUser must apply nothing; owner present: {after_c!r}"
    )
    assert after_c == after_b, (
        f"the denied {{env:c1,owner:o1}} must not partially apply env=c1; tags {after_c!r}"
    )
    assert_denied(tag(owner="x1"), "ForAllValues: {owner}")
    absent_all = _outcome(lambda: me.get_user(UserName=target))
    assert absent_all == ("OK", None), (
        f"ForAllValues over a request with NO aws:TagKeys is true, so GetUser must be allowed; "
        f"got {absent_all!r}"
    )

    # ---- Swap the operator in place: same policy name, same keys, ForAnyValue.
    iam.put_user_policy(UserName=caller, PolicyName=_POLICY, PolicyDocument=_doc(
        "ForAnyValue:StringEquals", target_arn, caller_arn, "iam:ListGroupsForUser"))
    stored = iam.get_user_policy(UserName=caller, PolicyName=_POLICY)["PolicyDocument"]
    stored = json.loads(stored) if isinstance(stored, str) else stored
    assert "ForAnyValue:StringEquals" in stored["Statement"][0]["Condition"], (
        f"the stored document must now carry ForAnyValue; got {stored!r}"
    )
    # Barrier: the new sentinel is allowed AND the old one denied, three times running, as the
    # minted user. No asserted outcome is read to decide that the swap has landed.
    streak = {"n": 0}

    def swapped():
        ok = (sentinel("iam:ListGroupsForUser") == "OK"
              and sentinel("iam:ListAttachedUserPolicies") == "AccessDenied")
        streak["n"] = streak["n"] + 1 if ok else 0
        return streak["n"]

    _poll(swapped, lambda n: n >= 3, timeout_s=120, interval_s=2,
          description="the ForAnyValue version replaces the ForAllValues one for the minted user")

    # ---- ForAnyValue:StringEquals [env, tier]; over an empty key set ForAnyValue is false.
    assert tag(env="a2") == ("OK", None), "ForAnyValue: {env} intersects {env,tier}"
    _await_tags(me, target, {"env": "a2", "tier": "t1"},
                "after {env:a2} the target carries env=a2 (tier=t1 kept)")
    assert tag(env="b2", tier="t2") == ("OK", None), "ForAnyValue: {env,tier} intersects"
    _await_tags(me, target, {"env": "b2", "tier": "t2"},
                "after {env:b2,tier:t2} the target carries env=b2,tier=t2")
    inverted = tag(env="c2", owner="o2")
    assert inverted == ("OK", None), (
        f"INVERSION: {{env,owner}} was denied under ForAllValues and must be allowed under "
        f"ForAnyValue (env matches); got {inverted!r}"
    )
    _await_tags(me, target, {"env": "c2", "tier": "t2", "owner": "o2"},
                "the now-allowed {env:c2,owner:o2} is applied in full (owner present)")
    assert_denied(tag(owner="x2"), "ForAnyValue: {owner} (no key in the set)")
    assert _tags_of(me, target)["owner"] == "o2", "the denied {owner:x2} must not overwrite owner"
    absent_any = _outcome(lambda: me.get_user(UserName=target))
    assert absent_any[0] == "AccessDenied", (
        f"INVERSION: ForAnyValue over a request with NO aws:TagKeys is false, so GetUser must now "
        f"be AccessDenied; got {absent_any!r}"
    )
    no_allow = (
        f"User: {caller_arn} is not authorized to perform: iam:GetUser on resource: user {target} "
        f"because no identity-based policy allows the iam:GetUser action"
    )
    absent_message = absent_any[1]
    expected = _with_authorization_details(no_allow, absent_message)
    assert absent_message == expected, (
        f"the key-less GetUser denial must be for lack of an allow, exactly {expected!r}; "
        f"got {absent_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
