"""list-code-repositories-reflects-created."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-code-repositories-reflects-created"
GROUP = 'lifecycle'
SERVICES = ['sagemaker']

def _create_code_repository(ctx, name=None):
    sm = ctx.client("sagemaker")
    name = name or ctx.unique_name("sim2real-behav-coderepo-")
    arn = sm.create_code_repository(
        CodeRepositoryName=name,
        GitConfig={
            "RepositoryUrl": "https://git.example.com/sim2real/sample-notebooks.git",
            "Branch": "main",
        },
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["CodeRepositoryArn"]
    ctx.on_cleanup(lambda: _delete_code_repository(sm, name))
    return name, arn


def _delete_code_repository(sm, name):
    """Teardown: delete the repository; run() may already have, and DeleteCodeRepository then
    answers ValidationException "Cannot find CodeRepository: <arn>"."""
    from botocore.exceptions import ClientError

    try:
        sm.delete_code_repository(CodeRepositoryName=name)
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] != "ValidationException" or not err.get("Message", "").startswith("Cannot find CodeRepository"):
            raise


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListCodeRepositories filtered by NameContains on the check's own name lists the created
    repository and stops listing it once the repository is deleted.
    """
    sm = ctx.client("sagemaker")
    name, arn = _create_code_repository(ctx)

    def _names():
        out = set()
        resp = sm.list_code_repositories(NameContains=name)
        for s in resp.get("CodeRepositorySummaryList", []):
            out.add(s["CodeRepositoryName"])
        return out

    names = _poll_until(
        _names,
        lambda s: name in s,
        timeout_s=30,
        interval_s=2,
        description=f"ListCodeRepositories(NameContains={name}) surfaces {name}",
    )
    assert name in names, f"expected {name} in ListCodeRepositories(NameContains={name}), got {names}"

    sm.delete_code_repository(CodeRepositoryName=name)

    names_after_delete = _poll_until(
        _names,
        lambda s: name not in s,
        timeout_s=30,
        interval_s=2,
        description=f"ListCodeRepositories(NameContains={name}) drops {name} after delete",
    )
    assert name not in names_after_delete, (
        f"expected {name} absent from ListCodeRepositories after delete, got {names_after_delete}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
