"""delete-investigation-group-idempotent-then-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-investigation-group-idempotent-then-not-found"
GROUP = "state"
SERVICES = ["aiops"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:aiops-investigation-group")
def run(ctx) -> None:
    """DeleteInvestigationGroup removes the group; a second delete on the same (already-deleted)
    identifier is rejected with ResourceNotFoundException (not idempotent in practice), and the
    group then 404s on Get too."""
    aiops = ctx.client("aiops")
    role_arn = _create_role(ctx)
    _name, arn = _create_group(ctx, aiops, role_arn)
    _wait_until_visible(aiops, arn)

    # First delete removes the group. Immediately after create (even once visible via a
    # successful Get), a Delete can still transiently 404 against an eventually-consistent
    # replica; retry briefly before treating it as a real failure.
    resp1 = _retry_not_found(lambda: aiops.delete_investigation_group(identifier=arn))
    status1 = resp1["ResponseMetadata"]["HTTPStatusCode"]
    assert status1 == 200, f"expected first DeleteInvestigationGroup to return 200, got {status1}"

    # Second delete on the same (now-gone) identifier is rejected: empirically NOT idempotent.
    code, message = _error(lambda: aiops.delete_investigation_group(identifier=arn))
    assert code == "ResourceNotFoundException", (
        f"expected second DeleteInvestigationGroup on a gone identifier to fail with "
        f"ResourceNotFoundException, got {code!r}"
    )
    expected = "InvestigationGroup does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    code, message = _error(lambda: aiops.get_investigation_group(identifier=arn))
    assert code == "ResourceNotFoundException", (
        f"expected GetInvestigationGroup on the deleted identifier to fail with "
        f"ResourceNotFoundException, got {code!r}"
    )
    expected = "InvestigationGroup does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "aiops.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _error(fn):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _wait_until_visible(aiops, arn: str, timeout_s: float = 20.0) -> None:
    """CreateInvestigationGroup's synchronous response can momentarily race ahead of the
    backend record actually becoming readable; poll GetInvestigationGroup until it 404s no
    more, so subsequent calls in the check aren't racing create's own propagation."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            aiops.get_investigation_group(identifier=arn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            last_exc = exc
            time.sleep(1.5)
    raise last_exc


def _retry_not_found(fn, timeout_s: float = 15.0):
    """Retry a call that can transiently 404 against an eventually-consistent replica right
    after the resource was created (even after an initial visibility check succeeded)."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            last_exc = exc
            time.sleep(1.5)
    raise last_exc


def _delete_if_present(aiops, arn: str) -> None:
    """Teardown for a group the check itself deletes: an already-gone group is the goal state."""
    try:
        aiops.delete_investigation_group(identifier=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-aiops-role-")
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST_POLICY)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _create_group(ctx, aiops, role_arn: str, **kwargs):
    name = ctx.unique_name("sim2real-ig-")
    deadline = time.monotonic() + 150.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = aiops.create_investigation_group(name=name, roleArn=role_arn, **kwargs)
            arn = resp["arn"]
            ctx.on_cleanup(lambda a=arn: _delete_if_present(aiops, a))
            return name, arn
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if (
                code == "ResourceNotFoundException"
                or code == "ServiceQuotaExceededException"
                or (code == "ValidationException" and "assume" in msg.lower())
            ):
                last_exc = exc
                time.sleep(5.0)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
