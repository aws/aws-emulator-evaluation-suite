"""singleton-second-create-conflict-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "singleton-second-create-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["aiops"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:aiops-investigation-group")
def run(ctx) -> None:
    """Only one investigation group is allowed per account/Region: a second CreateInvestigationGroup is rejected with ServiceQuotaExceededException, leaving the first group as the sole entry."""
    aiops = ctx.client("aiops")
    role_arn = _create_role(ctx)

    name_a, arn_a = _create_group(ctx, aiops, role_arn)

    name_b = ctx.unique_name("sim2real-ig-second-")
    code, message = _error(lambda: aiops.create_investigation_group(name=name_b, roleArn=role_arn))
    assert code == "ServiceQuotaExceededException", code
    expected = "Cannot create another investigation group."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: group B was never created. Group A remains present (it may not be the
    # sole entry if another check is concurrently holding/creating its own group at the
    # instant we list, so we assert containment rather than exact singleton count here).
    listed = aiops.list_investigation_groups(maxResults=50)["investigationGroups"]
    listed_arns = {g["arn"] for g in listed}
    assert arn_a in listed_arns, (arn_a, listed_arns)
    assert all(g["name"] != name_b for g in listed), (name_b, listed)

    # Positive control: the first group is still fully usable.
    got = aiops.get_investigation_group(identifier=arn_a)
    assert got["name"] == name_a, got
    assert got["arn"] == arn_a, got

    # Restore: the rejection above was the singleton state, not name_b itself. Free the slot
    # and reissue the IDENTICAL call — it must now succeed.
    resp_del = aiops.delete_investigation_group(identifier=arn_a)
    assert resp_del["ResponseMetadata"]["HTTPStatusCode"] == 200, resp_del
    _, arn_b = _create_group(ctx, aiops, role_arn, name=name_b)
    assert arn_b != arn_a, (arn_b, arn_a)

    got_b = aiops.get_investigation_group(identifier=arn_b)
    assert got_b["name"] == name_b, got_b
    assert got_b["arn"] == arn_b, got_b


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


def _delete_if_present(aiops, arn: str) -> None:
    """Teardown for a group the check may itself delete: an already-gone group is the goal state."""
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


def _create_group(ctx, aiops, role_arn: str, name: str | None = None, **kwargs):
    if name is None:
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
