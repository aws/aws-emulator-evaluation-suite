"""concurrent-role-creation-race."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-role-creation-race"
GROUP = "state-machine"
SERVICES = ["iam"]

_TRUST_POLICY = (
    '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", '
    '"Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}'
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """N racers concurrently CreateRole with the SAME RoleName: exactly one must
    win and the rest must get EntityAlreadyExists -- IAM name uniqueness must hold
    under contention."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-roleconcur-")
    ctx.on_cleanup(lambda: _best_effort_delete_role(iam, role_name))

    n_racers = 8

    def _racer(_i: int):
        try:
            iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=_TRUST_POLICY,
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            return ("ok", None)
        except ClientError as exc:
            return ("error", exc.response["Error"]["Code"], exc.response["Error"].get("Message", ""))

    results = []
    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        futures = [pool.submit(_racer, i) for i in range(n_racers)]
        for fut in as_completed(futures):
            results.append(fut.result())

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]

    assert len(successes) == 1, f"expected exactly 1 winner, got {len(successes)}: {results}"
    assert len(failures) == n_racers - 1, (
        f"expected {n_racers - 1} losers, got {len(failures)}: {results}"
    )
    assert all(code == "EntityAlreadyExists" for _, code, _ in failures), (
        f"all losers must get EntityAlreadyExists, got {failures}"
    )
    expected = f"Role with name {role_name} already exists."
    for _, _, message in failures:
        assert message == expected, f"loser message {message!r}, expected {expected!r}"

    # role must exist exactly once and be usable
    got = iam.get_role(RoleName=role_name)["Role"]
    assert got["RoleName"] == role_name, (
        f"expected role {role_name!r} to exist after the race, got {got['RoleName']!r}"
    )


def _best_effort_delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
