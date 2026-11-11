"""concurrent-create-investigation-group-race."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-investigation-group-race"
GROUP = "concurrency"
SERVICES = ["aiops"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:aiops-investigation-group")
def run(ctx) -> None:
    """Concurrent CreateInvestigationGroup racers each either create a group or fail with
    ServiceQuotaExceededException 'Cannot create another investigation group.', at least one wins,
    every winner is gettable and listed, and a further create after the race gets that refusal."""
    aiops = ctx.client("aiops")
    role_arn = _create_role(ctx)

    winners: list[tuple[str, str]] = []
    losers: list[tuple[str, dict]] = []
    for _attempt in range(3):
        # Claim the singleton slot (waiting out a group another run holds), then free it to race.
        _name0, arn0 = _create_group(ctx, aiops, role_arn)
        ctx.on_cleanup(lambda a=arn0: _delete_group(aiops, a))
        aiops.delete_investigation_group(identifier=arn0)

        names = [ctx.unique_name(f"sim2real-race{i}-") for i in range(5)]

        def _do_attempt(name: str):
            try:
                resp = aiops.create_investigation_group(name=name, roleArn=role_arn)
                return ("ok", name, resp["arn"])
            except ClientError as exc:
                return ("error", name, exc.response["Error"])

        with ThreadPoolExecutor(max_workers=len(names)) as pool:
            results = list(pool.map(_do_attempt, names))

        winners = [(name, arn) for status, name, arn in results if status == "ok"]
        losers = [(name, err) for status, name, err in results if status == "error"]
        for _name, arn in winners:
            ctx.on_cleanup(lambda a=arn: _delete_group(aiops, a))
        # No winner means a group created elsewhere took the freed slot first: claim it again.
        if winners:
            break

    assert winners, f"no racer created a group: losers={losers}"
    for name, err in losers:
        assert (err.get("Code"), err.get("Message")) == _QUOTA_ERROR, f"{name}: {err}"

    listed = {g["arn"] for g in aiops.list_investigation_groups(maxResults=50)["investigationGroups"]}
    for winner_name, winner_arn in winners:
        got = aiops.get_investigation_group(identifier=winner_arn)
        assert got["arn"] == winner_arn, f"expected arn {winner_arn}, got {got.get('arn')}"
        assert got["name"] == winner_name, f"expected name {winner_name}, got {got.get('name')}"
        assert winner_arn in listed, f"winner {winner_arn} not visible in list"

    # With a group in place, a create outside any race is refused.
    try:
        extra = aiops.create_investigation_group(
            name=ctx.unique_name("sim2real-ig-extra-"), roleArn=role_arn)
    except ClientError as exc:
        err = exc.response["Error"]
        assert (err.get("Code"), err.get("Message")) == _QUOTA_ERROR, err
    else:
        ctx.on_cleanup(lambda a=extra["arn"]: _delete_group(aiops, a))
        raise AssertionError(f"a second investigation group was created: {extra['arn']}")


_QUOTA_ERROR = ("ServiceQuotaExceededException", "Cannot create another investigation group.")


def _delete_group(aiops, arn: str) -> None:
    """Delete one investigation group; one already gone counts as deleted."""
    try:
        aiops.delete_investigation_group(identifier=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
