"""create-invalid-name-pattern-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-invalid-name-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["aiops"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:aiops-investigation-group")
def run(ctx) -> None:
    """A name containing a character outside the allowed pattern is rejected with ValidationException and no group is created."""
    aiops = ctx.client("aiops")
    role_arn = _create_role(ctx)

    bad_name = ctx.unique_name("sim2real-ig-") + "#bad%"
    code, message = _error(lambda: aiops.create_investigation_group(name=bad_name, roleArn=role_arn))
    assert code == "ValidationException", f"expected ValidationException for name {bad_name!r}, got {code!r}"
    expected = r"1 validation error detected: Value at 'name' failed to satisfy constraint: Member must satisfy regular expression pattern: [\-_A-Za-z0-9\[\]\(\)\{\}\.:!?@; ]+"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no group with that name was created.
    listed = aiops.list_investigation_groups(maxResults=50)["investigationGroups"]
    assert all(g["name"] != bad_name for g in listed), (
        f"rejected name {bad_name!r} nonetheless appeared in ListInvestigationGroups: {listed!r}"
    )

    # Positive control: a validly-named group succeeds.
    good_name, arn = _create_group(ctx, aiops, role_arn)
    got = aiops.get_investigation_group(identifier=arn)
    assert got["name"] == good_name, f"expected GetInvestigationGroup name {good_name!r}, got {got['name']!r}"


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
            ctx.on_cleanup(lambda a=arn: aiops.delete_investigation_group(identifier=a))
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
