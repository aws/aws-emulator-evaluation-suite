"""describe-compute-environments-paginates-with-max-results."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-compute-environments-paginates-with-max-results"
GROUP = "compute-environments"
SERVICES = ["batch", "iam"]

_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "batch.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}
_SERVICE_ROLE_POLICY = "arn:aws:iam::aws:policy/service-role/AWSBatchServiceRole"


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last saw {last!r}")


def _delete_role(iam, role_name):
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=_SERVICE_ROLE_POLICY)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _service_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-batch-unmgd-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_TRUST),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SERVICE_ROLE_POLICY)
    return arn


def _teardown_ce(bat, name):
    if not bat.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"]:
        return
    bat.update_compute_environment(computeEnvironment=name, state="DISABLED")
    _poll_until(
        lambda: bat.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"][0]["status"],
        lambda s: s in ("VALID", "INVALID"),
        description=f"compute environment {name} disabled",
    )
    deadline = time.monotonic() + 300.0
    while True:
        try:
            bat.delete_compute_environment(computeEnvironment=name)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClientException" or time.monotonic() > deadline:
                raise
            time.sleep(5)
    _poll_until(
        lambda: bat.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"],
        lambda envs: not envs or envs[0]["status"] == "DELETED",
        timeout_s=300.0,
        interval_s=5.0,
        description=f"compute environment {name} deleted",
    )


def _create_ce(ctx, bat, role_arn):
    name = ctx.unique_name("sim2real-behav-ce-")
    last_exc = None
    for attempt in range(10):
        try:
            bat.create_compute_environment(
                computeEnvironmentName=name,
                type="UNMANAGED",
                state="ENABLED",
                serviceRole=role_arn,
                tags={"sim2real:managed": "true"},
            )
            break
        except ClientError as exc:
            msg = exc.response["Error"].get("Message", "").lower()
            if "cannot be assumed" not in msg and "not authorized" not in msg and "sts:assumerole" not in msg:
                raise
            last_exc = exc
            time.sleep(4)
    else:
        raise last_exc
    ctx.on_cleanup(lambda: _teardown_ce(bat, name))
    ce = _poll_until(
        lambda: bat.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"][0],
        lambda c: c["status"] in ("VALID", "INVALID"),
        description=f"compute environment {name} settles",
    )
    assert ce["status"] == "VALID", f"compute environment did not validate: {ce.get('statusReason')!r}"
    return name


def _paginate(bat, max_results):
    """Every page of DescribeComputeEnvironments(maxResults=max_results), unfiltered."""
    pages = []
    token = None
    while True:
        kwargs = {"maxResults": max_results}
        if token:
            kwargs["nextToken"] = token
        page = bat.describe_compute_environments(**kwargs)
        pages.append(page)
        token = page.get("nextToken")
        if not token:
            return pages


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DescribeComputeEnvironments with maxResults below the account's environment count pages
    through nextToken, holding at most maxResults per page and covering each of this check's own
    environments exactly once; the final page carries no nextToken."""
    bat = ctx.client("batch")
    role_arn = _service_role(ctx)
    names = [_create_ce(ctx, bat, role_arn) for _ in range(3)]

    pages = _paginate(bat, max_results=1)
    for page in pages:
        assert len(page["computeEnvironments"]) <= 1, (
            f"a page at maxResults=1 must hold at most 1 environment, got {len(page['computeEnvironments'])}"
        )
    assert not pages[-1].get("nextToken"), "the final page must carry no nextToken"

    seen = [ce["computeEnvironmentName"] for page in pages for ce in page["computeEnvironments"]]
    for name in names:
        assert seen.count(name) == 1, (
            f"paginating at maxResults=1 must return {name!r} exactly once, got it {seen.count(name)} time(s)"
        )

    scoped = bat.describe_compute_environments(computeEnvironments=names)["computeEnvironments"]
    assert sorted(ce["computeEnvironmentName"] for ce in scoped) == sorted(names), (
        f"a call scoped to this check's own names must return exactly those names, got "
        f"{sorted(ce['computeEnvironmentName'] for ce in scoped)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
