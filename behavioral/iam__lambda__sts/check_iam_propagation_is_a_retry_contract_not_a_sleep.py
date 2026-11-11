"""iam-propagation-is-a-retry-contract-not-a-sleep."""

from __future__ import annotations

import io
import json
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "iam-propagation-is-a-retry-contract-not-a-sleep"

GROUP = "consistency"

SERVICES = ["iam", "lambda", "sts"]

# The documented rejection code each consumer may produce while the role is not yet effective for
# it: AccessDenied from sts:AssumeRole, InvalidParameterValueException ("The role defined for the
# function cannot be assumed by Lambda.") from lambda:CreateFunction. Any other code is a failure.
_WINDOW_CODES = {
    "assume-role": "AccessDenied",
    "create-function": "InvalidParameterValueException",
}
_WINDOW_MESSAGE = {"create-function": "cannot be assumed"}

# AWS guidance for role propagation is "wait several seconds"; 60s per consumer is far beyond
# typical convergence, so a timeout here means broken, not slow.
_DEADLINE_S = 60.0


def _error(fn) -> tuple[str, str]:
    """The AWS error (code, message) raised by fn(), or raise if fn() unexpectedly SUCCEEDS."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        "the call was expected to be rejected by the service but it SUCCEEDED -- a target that "
        "accepts this input is more broken than one that returns the wrong error code"
    )


def _zip_handler() -> bytes:
    """A dependency-free Lambda deployment package, built in memory at a fixed mtime."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo("index.py")
        info.date_time = (1980, 1, 1, 0, 0, 0)
        info.external_attr = 0o644 << 16
        zf.writestr(info, "def handler(event, context):\n    return {'ok': True}\n")
    return buf.getvalue()


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A fresh IAM role becomes usable by STS and Lambda through a bounded retry: rejections use one
    documented code per consumer, both consumers converge in the deadline, no rejected create leaves
    a partial function, and STS answers AccessDenied for a role that does not exist.
    """
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    lam = ctx.client("lambda")
    caller = sts.get_caller_identity()
    account = caller["Account"]

    role = ctx.unique_name("sim2real-behav-iamprop-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "sts:AssumeRole",
            },
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            },
        ],
    }
    created = iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role))
    role_arn = created["Role"]["Arn"]

    # ---- assertion 5: IAM is read-your-write WITHIN IAM, on the first attempt ---------------
    # The window is about other services' view of the role, not about IAM's own store. A target
    # that lags GetRole fails here; one that lags nothing fails the warm-role contrast below.
    same = iam.get_role(RoleName=role)["Role"]
    assert same["Arn"] == role_arn, (
        f"GetRole immediately after CreateRole returned {same['Arn']!r}, expected {role_arn!r}. "
        f"IAM's own store is read-your-write; only OTHER services lag."
    )

    # ---- act: fire both consumers from the moment CreateRole returned -----------------------
    zip_bytes = _zip_handler()
    fn_first = ctx.unique_name("sim2real-behav-iamprop-fn1-")
    fn_warm = ctx.unique_name("sim2real-behav-iamprop-fn2-")
    ctx.on_cleanup(lambda: _delete_function(lam, fn_first))
    ctx.on_cleanup(lambda: _delete_function(lam, fn_warm))

    def _create_function(name: str):
        lam.create_function(
            FunctionName=name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": zip_bytes},
            Timeout=10,
            Tags={"sim2real": CHECK},
        )

    consumers = {
        "assume-role": lambda: sts.assume_role(
            RoleArn=role_arn, RoleSessionName="sim2real-behav-iamprop"
        ),
        "create-function": lambda: _create_function(fn_first),
    }
    with ThreadPoolExecutor(max_workers=len(consumers)) as pool:
        futures = {
            name: pool.submit(_attempt_until_accepted, fn, _DEADLINE_S)
            for name, fn in consumers.items()
        }
        logs = {name: f.result() for name, f in futures.items()}

    # ---- assertion 1: every failure is the ONE documented code for that consumer ------------
    for name, log in logs.items():
        wrong = [a for a in log if a["code"] not in ("OK", _WINDOW_CODES[name])]
        assert not wrong, (
            f"{name} produced {len(wrong)} rejection(s) outside the documented propagation code "
            f"{_WINDOW_CODES[name]!r}: {[(a['attempt'], a['code'], a['message'][:120]) for a in wrong[:4]]!r}. "
            f"A caller can only retry through a window whose failures it can recognise, so an "
            f"undocumented code -- and especially a 5xx -- makes the window unhandleable."
        )
        assert all(a["status"] != 5 for a in log), (
            f"{name} produced a 5xx during the propagation window: "
            f"{[(a['attempt'], a['code'], a['status']) for a in log if a['status'] == 5]!r}. "
            f"A not-yet-effective role is a client-side condition, never a server error."
        )

    # ---- assertion 2: the window message NAMES the trust relationship ----------------------
    # Vacuous if the region converged on attempt 1 -- which is correct, and is why the warm-role
    # contrast below is what makes the propagation arms mean anything.
    for name, needle in _WINDOW_MESSAGE.items():
        offenders = [
            a for a in logs[name] if a["code"] != "OK" and needle not in a["message"]
        ]
        assert not offenders, (
            f"{len(offenders)} of {name}'s window rejections did not mention {needle!r}: "
            f"{[a['message'][:160] for a in offenders[:3]]!r}. The message is how a caller "
            f"distinguishes 'the role is not effective yet' from 'the trust policy is wrong', and "
            f"retrying the second forever is a hang, not a recovery."
        )

    # ---- assertion 4: both consumers converged inside the deadline -------------------------
    for name, log in logs.items():
        assert log[-1]["code"] == "OK", (
            f"{name} NEVER succeeded within {_DEADLINE_S}s over {len(log)} attempts. This is "
            f"'never arrived', not 'arrived late': the full per-attempt log is "
            f"{[(a['attempt'], a['elapsed_ms'], a['code']) for a in log]!r}"
        )

    # ---- assertion 6: the first-failure evidence was not slept past -------------------------
    for name, log in logs.items():
        if len(log) >= 3:
            third = log[2]["elapsed_ms"]
            assert third < 1500, (
                f"{name}'s third attempt landed {third}ms after the first, so the attempts were "
                f"paced by a delay rather than issued back-to-back. This check IS the anti-sleep "
                f"contract: a fixed sleep between early attempts hides whether the window was ever "
                f"observed. Log: {[(a['attempt'], a['elapsed_ms'], a['code']) for a in log]!r}"
            )

    # ---- assertion 3: the documented code set is STABLE across the transition ---------------
    # Not strict monotonicity: AWS can transiently reject a role it already accepted. What holds is
    # that post-convergence rejections draw from the same one-element code set and still converge.
    post: dict[str, list[dict]] = {"assume-role": [], "create-function": []}
    for i in range(5):
        post["assume-role"] += _attempt_until_accepted(
            lambda: sts.assume_role(
                RoleArn=role_arn, RoleSessionName=f"sim2real-behav-iamprop-{i}"
            ),
            _DEADLINE_S,
        )
    post["create-function"] += _attempt_until_accepted(
        lambda: _create_function(fn_warm), _DEADLINE_S
    )
    for name, log in post.items():
        novel = [a for a in log if a["code"] not in ("OK", _WINDOW_CODES[name])]
        assert not novel, (
            f"after the role had already been accepted, {name} produced a code outside the one it "
            f"produces during the window ({_WINDOW_CODES[name]!r}): "
            f"{[(a['attempt'], a['code'], a['message'][:120]) for a in novel[:4]]!r}. A caller that "
            f"has learned to retry one code cannot handle a second one appearing later."
        )
        assert log[-1]["code"] == "OK", (
            f"{name} stopped converging AFTER the role had already been accepted once: "
            f"{[(a['attempt'], a['elapsed_ms'], a['code']) for a in log[-8:]]!r}"
        )

    # ---- no PARTIAL success: a rejected CreateFunction created nothing ----------------------
    # Deterministic and unconditional. Every attempt in the window either created the function or
    # created nothing; there is exactly one function under that name and it carries the role that
    # was asked for. A target that half-applied a rejected create fails here.
    described = lam.get_function(FunctionName=fn_first)["Configuration"]
    assert described["Role"] == role_arn, (
        f"the function created through the propagation window reports role "
        f"{described['Role']!r}, expected {role_arn!r}"
    )
    assert described["State"] != "Failed", (
        f"the function created through the propagation window is in state "
        f"{described['State']!r} / {described.get('StateReason')!r} -- a create that returned "
        f"success must not leave a broken function behind"
    )
    names = []
    for page in lam.get_paginator("list_functions").paginate():
        names += [f["FunctionName"] for f in page["Functions"]]
    assert names.count(fn_first) == 1, (
        f"ListFunctions reports {names.count(fn_first)} functions named {fn_first!r}. Every "
        f"rejected attempt in the window must have created NOTHING; more than one means a refused "
        f"create was partially applied."
    )

    # ---- negative: STS does not disclose that a role does not exist ------------------------
    never = ctx.unique_name("sim2real-behav-iamprop-absent-")
    absent_arn = f"arn:aws:iam::{account}:role/{never}"
    code, message = _error(
        lambda: sts.assume_role(
            RoleArn=absent_arn, RoleSessionName="sim2real-behav-absent"
        )
    )
    assert code == "AccessDenied", (
        f"sts:AssumeRole on a role that was never created was rejected with {code!r}, expected "
        f"'AccessDenied'. STS must not distinguish 'this role does not exist' from 'you may not "
        f"assume it' -- a target that answers NoSuchEntity or a 404 here leaks the existence of "
        f"every role name an unauthorised caller cares to guess."
    )
    expected = (
        f"User: {caller['Arn']} is not authorized to perform: sts:AssumeRole on resource: "
        f"{absent_arn}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect-absent: the role genuinely does not exist, so the AccessDenied above is deliberate
    # non-disclosure rather than a stale cache of a role that was deleted.
    absent_code, absent_message = _error(lambda: iam.get_role(RoleName=never))
    assert absent_code == "NoSuchEntity", (
        f"iam:GetRole on {never!r} returned {absent_code!r}, expected 'NoSuchEntity'. Without this "
        f"the AccessDenied above could simply mean the role existed and was not assumable."
    )
    expected = f"The role with name {never} cannot be found."
    assert absent_message == expected, f"expected message {expected!r}, got {absent_message!r}"

    # control: the same call against the role that DOES exist succeeds, in the same breath -- so
    # the AccessDenied was about that ARN and not about the caller's own sts:AssumeRole permission.
    live = sts.assume_role(
        RoleArn=role_arn, RoleSessionName="sim2real-behav-iamprop-ctl"
    )
    assert live["AssumedRoleUser"]["Arn"].startswith("arn:aws:sts::"), (
        f"control: assuming the real role returned {live['AssumedRoleUser']!r}"
    )

    # ---- the credentials the control returned are REAL, and carry the role's identity -------
    # Off-response and deterministic: the session is used, not merely received, and the identity it
    # reports is an exact string derived from the role name and the session name that were passed
    # in. A target that mints a plausible-looking credential blob it cannot then authenticate fails
    # here, and so does one that reports the CALLER's identity for an assumed session.
    creds = live["Credentials"]
    for field in ("AccessKeyId", "SecretAccessKey", "SessionToken"):
        assert creds.get(field), (
            f"the assumed-role credentials omitted {field!r}: keys present were "
            f"{sorted(creds)!r}"
        )
    assert creds["Expiration"] is not None, "the assumed-role credentials never expire"
    # ctx.client(..., creds=...) keeps this target's endpoint and config with the assumed identity;
    # a bare boto3.Session() would carry no endpoint_url.
    who = ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    ).get_caller_identity()
    want_arn = f"arn:aws:sts::{account}:assumed-role/{role}/sim2real-behav-iamprop-ctl"
    assert who["Arn"] == want_arn, (
        f"sts:GetCallerIdentity on the assumed session reported {who['Arn']!r}, expected "
        f"{want_arn!r}. An assumed session's identity is the ROLE plus the session name it was "
        f"given -- not the principal that assumed it, and not the role ARN."
    )
    assert who["Account"] == account, (
        f"the assumed session reported account {who['Account']!r}, expected {account!r}"
    )


def _attempt_until_accepted(fn, deadline_s: float) -> list[dict]:
    """Retry the operation until it is accepted, recording every attempt.

    The first three attempts are issued back-to-back, so a recorded rejection is real evidence of
    the window rather than an artifact of a chosen interval; later attempts are paced.
    """
    log: list[dict] = []
    start = time.monotonic()
    while True:
        try:
            fn()
            log.append(
                {
                    "attempt": len(log) + 1,
                    "elapsed_ms": int((time.monotonic() - start) * 1000),
                    "code": "OK",
                    "message": "",
                    "status": 2,
                }
            )
            return log
        except ClientError as exc:
            http = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0)
            log.append(
                {
                    "attempt": len(log) + 1,
                    "elapsed_ms": int((time.monotonic() - start) * 1000),
                    "code": exc.response["Error"]["Code"],
                    "message": exc.response["Error"].get("Message", ""),
                    "status": http // 100,
                }
            )
            if time.monotonic() - start >= deadline_s:
                return log
            if len(log) >= 3:
                time.sleep(1.0)


def _delete_function(lam, name: str) -> None:
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
