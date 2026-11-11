"""inactive-access-key-is-refused-while-its-active-twin-succeeds."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "inactive-access-key-is-refused-while-its-active-twin-succeeds"
GROUP = "access_keys"
SERVICES = ["iam"]

_POLICY_NAME = "sim2real-behav-keystate-self-read"
_MARK = [{"Key": "sim2real", "Value": CHECK}]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Of two keys on one user, the Active one signs successfully while the Inactive one is refused
    with InvalidClientTokenId; activating it makes the same request succeed, and UpdateAccessKey on
    a deleted key id fails with NoSuchEntity.
    """
    iam = ctx.client("iam")

    user = ctx.unique_name("sim2real-keystate-user-")
    iam.create_user(UserName=user, Path="/", Tags=_MARK)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))
    user_arn = iam.get_user(UserName=user)["User"]["Arn"]

    iam.put_user_policy(
        UserName=user,
        PolicyName=_POLICY_NAME,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["iam:GetUser", "iam:ListUserTags"],
                "Resource": user_arn,
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user, PolicyName=_POLICY_NAME))

    live = iam.create_access_key(UserName=user)["AccessKey"]
    ctx.on_cleanup(lambda: _drop_key(iam, user, live["AccessKeyId"]))
    frozen = iam.create_access_key(UserName=user)["AccessKey"]
    ctx.on_cleanup(lambda: _drop_key(iam, user, frozen["AccessKeyId"]))
    assert live["AccessKeyId"] != frozen["AccessKeyId"], (
        f"the two keys must be distinct for the twin comparison to mean anything; both are "
        f"{live['AccessKeyId']!r}"
    )

    # Deactivated before it is ever used: signature validation can lag a revocation, so the refusal
    # under test is the key's initial state rather than a revocation that has to propagate.
    iam.update_access_key(
        UserName=user, AccessKeyId=frozen["AccessKeyId"], Status="Inactive"
    )

    statuses = _key_statuses(iam, user)
    assert statuses == {live["AccessKeyId"]: "Active", frozen["AccessKeyId"]: "Inactive"}, (
        f"the control plane must report exactly one Active key and one Inactive key before their "
        f"signing behaviour is compared: expected "
        f"{{{live['AccessKeyId']!r}: 'Active', {frozen['AccessKeyId']!r}: 'Inactive'}}, the "
        f"paginated ListAccessKeys reports {statuses!r}"
    )

    as_live = _signing_as(ctx, "iam", live)
    as_frozen = _signing_as(ctx, "iam", frozen)

    ok = _poll(
        lambda: _outcome(lambda: as_live.get_user(UserName=user)),
        lambda o: o == "OK",
        timeout_s=90,
        interval_s=3,
        description="the Active key becomes usable for the granted iam:GetUser",
    )
    assert ok == "OK", (
        f"the Active key holds a grant for iam:GetUser on its own user, so the real signed call must "
        f"succeed; expected 'OK', got {ok!r}"
    )

    refused, refused_msg = _rejected_code(lambda: as_frozen.get_user(UserName=user))
    assert refused == "InvalidClientTokenId", (
        f"the second key is Inactive, so the byte-identical signed request must be refused with "
        f"exactly InvalidClientTokenId -- an AUTHENTICATION failure, not AccessDenied; got "
        f"{refused!r}. An emulator that stores Status without consulting it in its signer accepts "
        f"this request, and one that answers AccessDenied is misclassifying a credential problem as "
        f"an authorization problem"
    )
    assert refused_msg == "The security token included in the request is invalid.", (
        f"the Inactive key's refusal must carry AWS's exact InvalidClientTokenId message; got "
        f"{refused_msg!r}"
    )
    unaffected = _outcome(lambda: as_live.get_user(UserName=user))
    assert unaffected == "OK", (
        f"the Active twin must still work immediately after the Inactive key was refused, so the "
        f"refusal was scoped to that one credential; expected 'OK', got {unaffected!r}"
    )

    iam.update_access_key(UserName=user, AccessKeyId=frozen["AccessKeyId"], Status="Active")
    now_active = _key_statuses(iam, user)
    assert now_active[frozen["AccessKeyId"]] == "Active", (
        f"the key must observably be Active before its effect is asserted: ListAccessKeys reports "
        f"{now_active!r}"
    )
    thawed = _poll(
        lambda: _outcome(lambda: as_frozen.get_user(UserName=user)),
        lambda o: o == "OK",
        timeout_s=90,
        interval_s=3,
        description="activating the second key makes the previously refused request succeed",
    )
    assert thawed == "OK", (
        f"activating the key must make the byte-identical request that was just refused succeed, "
        f"proving the refusal was the Status field's doing; expected 'OK', got {thawed!r}"
    )

    iam.delete_access_key(UserName=user, AccessKeyId=frozen["AccessKeyId"])
    after = _key_statuses(iam, user)
    assert after == {live["AccessKeyId"]: "Active"}, (
        f"after deleting the second key the paginated ListAccessKeys must report exactly the "
        f"surviving Active key: expected {{{live['AccessKeyId']!r}: 'Active'}}, got {after!r}"
    )
    dead, dead_msg = _rejected_code(
        lambda: iam.update_access_key(
            UserName=user, AccessKeyId=frozen["AccessKeyId"], Status="Inactive"
        )
    )
    assert dead == "NoSuchEntity", (
        f"UpdateAccessKey demonstrably worked on this key id moments ago, so after the delete it "
        f"must fail with exactly NoSuchEntity rather than succeeding against a ghost; got {dead!r}"
    )
    expected_dead = f"The Access Key with id {frozen['AccessKeyId']} cannot be found."
    assert dead_msg == expected_dead, (
        f"UpdateAccessKey on the deleted key id must carry AWS's exact NoSuchEntity message "
        f"{expected_dead!r}; got {dead_msg!r}"
    )


def _outcome(fn):
    """``"OK"`` on success, else the AWS error code."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code") or "NO_ERROR_CODE"
    return "OK"


def _rejected_code(fn):
    """``(code, message)`` of a call that must be refused; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code") or "NO_ERROR_CODE", err.get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    """Bounded retry with a deadline; raises on timeout.

    A newly created or activated key becomes usable asynchronously.
    """
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
    """A client for ``service`` signing as the principal that owns ``key``."""
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": key["AccessKeyId"],
            "aws_secret_access_key": key["SecretAccessKey"],
        },
    )


def _key_statuses(iam, user):
    """{AccessKeyId: Status} for the user, paginated."""
    out = {}
    for page in iam.get_paginator("list_access_keys").paginate(UserName=user):
        for meta in page["AccessKeyMetadata"]:
            out[meta["AccessKeyId"]] = meta["Status"]
    return out


def _drop_key(iam, user, access_key_id):
    """Teardown: the body deletes one key itself, so tolerate it already being gone."""
    try:
        iam.delete_access_key(UserName=user, AccessKeyId=access_key_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
