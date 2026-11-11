"""get-investigation-group-by-name-and-arn-equivalent."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-investigation-group-by-name-and-arn-equivalent"
GROUP = "state"
SERVICES = ["aiops"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:aiops-investigation-group")
def run(ctx) -> None:
    """GetInvestigationGroup by ARN returns the group's name and role, ListInvestigationGroups lists
    the same name/ARN pair once, and GetInvestigationGroup by name is refused with
    ResourceNotFoundException and the exact message although the model documents name lookup."""
    aiops = ctx.client("aiops")
    role_arn = _create_role(ctx)
    name, arn = _create_group(ctx, aiops, role_arn)
    by_arn = _wait_until_visible(aiops, arn)

    assert by_arn["arn"] == arn, f"expected arn={arn!r}, got {by_arn['arn']!r}"
    assert by_arn["name"] == name, f"expected name={name!r}, got {by_arn['name']!r}"
    assert by_arn["roleArn"] == role_arn, f"expected roleArn={role_arn!r}, got {by_arn['roleArn']!r}"

    listed = aiops.list_investigation_groups(maxResults=50)["investigationGroups"]
    matches = [g for g in listed if g["arn"] == arn]
    assert len(matches) == 1, f"expected exactly 1 listed group with arn={arn!r}, got {len(matches)}"
    assert matches[0]["name"] == name, f"expected listed name={name!r}, got {matches[0]['name']!r}"

    # The model documents `identifier` as the name or the ARN, but AWS never resolves an
    # existing group by name.
    try:
        result = aiops.get_investigation_group(identifier=name)
    except ClientError as exc:
        name_lookup_code = exc.response["Error"]["Code"]
        name_lookup_message = exc.response["Error"].get("Message")
    else:
        raise AssertionError(f"expected GetInvestigationGroup(identifier=<name>) to 404, it returned {result!r}")
    assert name_lookup_code == "ResourceNotFoundException", (
        f"expected GetInvestigationGroup(identifier=<name>) to 404 for an existing group "
        f"(name={name!r}, arn={arn!r}); got code={name_lookup_code!r}"
    )
    expected = "InvestigationGroup does not exist."
    assert name_lookup_message == expected, f"expected message {expected!r}, got {name_lookup_message!r}"


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


def _wait_until_visible(aiops, arn: str, timeout_s: float = 20.0):
    """CreateInvestigationGroup's synchronous response can momentarily race ahead of the
    backend record actually becoming readable; poll GetInvestigationGroup until it 404s no
    more, so subsequent calls in the check aren't racing create's own propagation."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return aiops.get_investigation_group(identifier=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            last_exc = exc
            time.sleep(1.5)
    raise last_exc


def _create_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-aiops-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": "audit"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _create_group(ctx, aiops, role_arn: str, **kwargs):
    name = ctx.unique_name("sim2real-ig-")
    kwargs.setdefault("tags", {"sim2real": "audit"})
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

