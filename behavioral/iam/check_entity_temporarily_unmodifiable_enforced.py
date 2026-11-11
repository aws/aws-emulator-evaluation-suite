"""entity-temporarily-unmodifiable-enforced."""
from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "entity-temporarily-unmodifiable-enforced"
GROUP = 'errors'
SERVICES = ['iam']


def _error(fn):
    """Call fn(); return its (Code, Message). An unexpected SUCCESS raises, so a target that
    accepts the call cannot read as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _assert_one_of(what, got, expected):
    """``got`` is a (Code, Message) pair equal to one of the ``expected`` {Code: Message} entries;
    a None message grades the code alone."""
    code, message = got
    assert code in expected, f"{what}: expected one of {sorted(expected)}, got {code!r}"
    if expected[code] is None:
        return
    assert message == expected[code], (
        f"{what}: expected message {expected[code]!r} for {code}, got {message!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=30, interval_s=3.0, description="condition"):
    import time as _t
    deadline = _t.monotonic() + timeout_s
    last = None
    while _t.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        _t.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After a user is deleted and recreated, each op returns either EntityTemporarilyUnmodifiable
    or its baseline outcome (the cooldown is a race), and the observed state must match that
    outcome."""
    iam = ctx.client("iam")
    UNMOD = "EntityTemporarilyUnmodifiable"
    user_name = ctx.unique_name("sim2real-behav-user-")
    tag = [{"Key": "sim2real", "Value": CHECK}]
    iam.create_user(UserName=user_name, Tags=tag)
    iam.delete_user(UserName=user_name)
    iam.create_user(UserName=user_name, Tags=tag)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    # message varies: the EntityTemporarilyUnmodifiable cooldown is a convergence race that IAM
    # almost always wins, so only its code is graded. NoSuchEntity alternatives grade exact messages.
    unmod_message = None
    no_login_profile = f"Login Profile for User {user_name} cannot be found."

    # UpdateUser: either rejected (path unchanged) or applied (path changed).
    try:
        iam.update_user(UserName=user_name, NewPath="/sim2real-behav/")
        updated = True
    except ClientError as exc:
        updated = False
        _assert_one_of(
            "UpdateUser",
            (exc.response["Error"]["Code"], exc.response["Error"].get("Message")),
            {UNMOD: unmod_message},
        )
    path = iam.get_user(UserName=user_name)["User"]["Path"]
    if updated:
        assert path == "/sim2real-behav/", "a successful UpdateUser must have applied the new path"
    else:
        assert path == "/", "a rejected UpdateUser must leave the path unchanged"

    # UpdateLoginProfile: no login profile exists yet on the fresh incarnation.
    _assert_one_of(
        "UpdateLoginProfile",
        _error(lambda: iam.update_login_profile(UserName=user_name, Password="Sim2Real!Behav1")),
        {UNMOD: unmod_message, "NoSuchEntity": no_login_profile},
    )

    # DeleteLoginProfile: same reasoning.
    _assert_one_of(
        "DeleteLoginProfile",
        _error(lambda: iam.delete_login_profile(UserName=user_name)),
        {UNMOD: unmod_message, "NoSuchEntity": no_login_profile},
    )

    # EnableMFADevice: the serial was never registered.
    enable_serial = f"sim2real-behav-{uuid.uuid4().hex}"
    _assert_one_of(
        "EnableMFADevice",
        _error(
            lambda: iam.enable_mfa_device(
                UserName=user_name,
                SerialNumber=enable_serial,
                AuthenticationCode1="123456",
                AuthenticationCode2="654321",
            )
        ),
        {UNMOD: unmod_message, "NoSuchEntity": f"MFA Device with serial number {enable_serial} does not exist."},
    )

    # DeactivateMFADevice: same reasoning.
    deactivate_serial = f"sim2real-behav-{uuid.uuid4().hex}"
    _assert_one_of(
        "DeactivateMFADevice",
        _error(
            lambda: iam.deactivate_mfa_device(UserName=user_name, SerialNumber=deactivate_serial)
        ),
        {UNMOD: unmod_message, "NoSuchEntity": f"MFA Device with serial number {deactivate_serial} does not exist."},
    )

    # ChangePassword acts on the CALLER, so mint an access key for the recreated user and call it
    # as them. Grant self-service change-password permission first, then poll past propagation.
    change_pw_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "iam:ChangePassword", "Resource": "*"}],
        }
    )
    iam.put_user_policy(
        UserName=user_name, PolicyName="sim2real-behav-change-password", PolicyDocument=change_pw_policy
    )
    ctx.on_cleanup(
        lambda: iam.delete_user_policy(
            UserName=user_name, PolicyName="sim2real-behav-change-password"
        )
    )
    key = iam.create_access_key(UserName=user_name)
    access_key_id = key["AccessKey"]["AccessKeyId"]
    secret_key = key["AccessKey"]["SecretAccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=access_key_id))
    user_client = ctx.client(
        "iam", creds={"aws_access_key_id": access_key_id, "aws_secret_access_key": secret_key}
    )
    auth_propagation_codes = {"InvalidClientTokenId", "SignatureDoesNotMatch", "AccessDenied"}

    result = _poll_until(
        lambda: _error(
            lambda: user_client.change_password(
                OldPassword="Sim2Real!Behav1", NewPassword="Sim2Real!Behav2"
            )
        ),
        lambda r: r[0] not in auth_propagation_codes,
        timeout_s=30,
        interval_s=3,
        description="ChangePassword reaches a post-propagation answer",
    )
    _assert_one_of(
        "ChangePassword",
        result,
        {UNMOD: unmod_message, "NoSuchEntity": f"Login Profile for User {user_name} cannot be found."},
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
