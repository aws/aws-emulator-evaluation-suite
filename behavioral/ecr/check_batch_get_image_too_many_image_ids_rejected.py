"""batch-get-image-too-many-image-ids-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Return the botocore error (code, message) from fn(); raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


CHECK = "batch-get-image-too-many-image-ids-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ecr']


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchGetImage with 101 imageIds exceeds the 100-image limit and is rejected with
    InvalidParameterException; the same call with 100 imageIds succeeds."""
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-behav-ecr-repo-")
    ecr.create_repository(repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))

    at_limit = [{"imageTag": f"missing-{i}"} for i in range(100)]
    ok = ecr.batch_get_image(repositoryName=name, imageIds=at_limit)
    assert len(ok["failures"]) == 100, (
        f"expected all 100 image ids to report a failure (none exist), got {ok['failures']}"
    )

    over_limit = at_limit + [{"imageTag": "missing-100"}]
    expected = (
        "Invalid parameter at 'imageIds' failed to satisfy constraint: 'Member must have "
        "length less than or equal to 100'"
    )
    code, message = _error(lambda: ecr.batch_get_image(repositoryName=name, imageIds=over_limit))
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}: {message!r}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
