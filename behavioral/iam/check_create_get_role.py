"""create-get-role."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

MINIMAL_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

CHECK = "create-get-role"
GROUP = 'role_lifecycle'
SERVICES = ['iam']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRole -> GetRole returns consistent configuration."""
    iam = ctx.client("iam")
    account = ctx.account
    name = ctx.unique_name("sim2real-behav-role-")
    path = f"/sim2real/{ctx.unique_name('p-')}/"
    iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY,
        Path=path,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda n=name: _quiet(lambda: iam.delete_role(RoleName=n)))
    resp = iam.get_role(RoleName=name)
    role = resp["Role"]
    assert role["RoleName"] == name, f"expected RoleName {name!r}, got {role['RoleName']!r}"
    expected_arn = f"arn:aws:iam::{account}:role{path}{name}"
    assert role["Arn"] == expected_arn, f"expected Arn {expected_arn!r}, got {role['Arn']!r}"
    assert role["Path"] == path, f"expected Path {path!r}, got {role['Path']!r}"
    # Trust policy round-trips (boto3 may return dict or URL-encoded string)
    trust = role["AssumeRolePolicyDocument"]
    if isinstance(trust, str):
        from urllib.parse import unquote

        trust = json.loads(unquote(trust))
    assert trust["Version"] == "2012-10-17", f"expected Version '2012-10-17', got {trust.get('Version')!r}"
    assert len(trust["Statement"]) == 1, f"expected exactly 1 statement, got {len(trust['Statement'])}"
    statement = trust["Statement"][0]
    assert statement["Effect"] == "Allow", f"expected Effect 'Allow', got {statement.get('Effect')!r}"
    assert statement["Principal"] == {"Service": "lambda.amazonaws.com"}, (
        f"expected Principal {{'Service': 'lambda.amazonaws.com'}}, got {statement.get('Principal')!r}"
    )
    assert statement["Action"] == "sts:AssumeRole", f"expected Action 'sts:AssumeRole', got {statement.get('Action')!r}"
    def _listed():
        return [r["RoleName"] for p in iam.get_paginator("list_roles").paginate(PathPrefix=path) for r in p["Roles"]]

    # IAM is eventually consistent: every read after a write converges within a bounded deadline.
    listed = _poll(_listed, lambda v: v == [name])
    assert listed == [name], f"expected ListRoles(PathPrefix) to list exactly the new role, got {listed!r}"

    iam.delete_role(RoleName=name)
    # Gone beat 1: GetRole answers NoSuchEntity.
    refused = _poll(lambda: _outcome(lambda: iam.get_role(RoleName=name)), bool)
    _assert_error(refused, "NoSuchEntity", 404)
    expected_message = f"The role with name {name} cannot be found."
    assert refused.get("Error", {}).get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.get("Error", {}).get("Message")!r}'
    # Gone beat 2: the check's own path lists nothing.
    listed = _poll(_listed, lambda v: not v)
    assert not listed, f"deleted role still listed under its path: {listed!r}"
    # Gone beat 3: a mutation on the dead role is refused.
    refused = _error(lambda: iam.update_role(RoleName=name, Description="x"))
    _assert_error(refused, "NoSuchEntity", 404)
    expected_message = f"The role with name {name} cannot be found."
    assert refused.get("Error", {}).get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.get("Error", {}).get("Message")!r}'


def _error(fn):
    """Call fn() and return its ClientError response; a call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


#: Bounded convergence for IAM's eventual consistency (the default class budget).
_CONVERGE_S = 120.0


def _poll(probe, done, timeout_s: float = _CONVERGE_S):
    """probe() until done(result) or the deadline; returns the last result (the caller asserts it)."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last) or time.monotonic() >= deadline:
            return last
        time.sleep(2.0)


def _outcome(fn):
    """fn()'s ClientError response, or {} while the call still succeeds (the poll retries it)."""
    try:
        fn()
    except ClientError as exc:
        return exc.response
    return {}


def _assert_error(resp, code, status):
    """Grade a refusal on code + HTTP status class (4xx vs 5xx) + the exact message."""
    err = resp.get("Error", {})
    got_status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert err.get("Code") == code, f"expected {code}, got {err.get('Code')!r}"
    lo = status // 100 * 100
    assert isinstance(got_status, int) and lo <= got_status < lo + 100, (
        f"expected an HTTP {lo // 100}xx (AWS answers {status}) for {code}, got {got_status!r}"
    )
    assert err.get("Message"), f"expected a non-empty {code} message, got {err!r}"


def _quiet(fn):
    """Teardown call that tolerates the resource already being gone (the body deletes it)."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
