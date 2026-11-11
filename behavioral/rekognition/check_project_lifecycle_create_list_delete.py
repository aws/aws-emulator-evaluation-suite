"""project-lifecycle-create-list-delete."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "project-lifecycle-create-list-delete"
GROUP = "state"
SERVICES = ["rekognition"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateProject transitions to CREATED, is visible via DescribeProjects, then DeleteProject removes it."""
    rek = ctx.client("rekognition")
    project_name = ctx.unique_name("sim2real-rek-project-")

    created = rek.create_project(
        ProjectName=project_name,
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-rek-project"},
    )
    project_arn = created["ProjectArn"]
    ctx.on_cleanup(lambda: _delete_project_ignore_missing(rek, project_arn))

    described = _poll_until(
        lambda: _find_project(rek, project_arn),
        lambda proj: proj is not None and proj["Status"] == "CREATED",
        timeout_s=60.0,
    )
    assert described["ProjectArn"] == project_arn, (
        f"expected DescribeProjects to reflect the created project {project_arn!r}, got {described['ProjectArn']!r}"
    )

    rek.delete_project(ProjectArn=project_arn)

    _poll_until(
        lambda: _find_project(rek, project_arn),
        lambda proj: proj is None,
        timeout_s=60.0,
    )

    code, message = _client_error(lambda: rek.delete_project(ProjectArn=project_arn))
    assert code == "ResourceNotFoundException", (
        f"expected re-deleting an already-deleted project {project_arn!r} to fail with "
        f"ResourceNotFoundException, got {code!r}"
    )
    assert message == f"Project {project_arn} does not exist", (
        f"re-deleting an already-deleted project {project_arn!r} returned message {message!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _find_project(rek, project_arn: str):
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = rek.describe_projects(**kwargs)
        for proj in resp.get("ProjectDescriptions", []):
            if proj["ProjectArn"] == project_arn:
                return proj
        token = resp.get("NextToken")
        if not token:
            return None


def _delete_project_ignore_missing(rek, project_arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        rek.delete_project(ProjectArn=project_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
