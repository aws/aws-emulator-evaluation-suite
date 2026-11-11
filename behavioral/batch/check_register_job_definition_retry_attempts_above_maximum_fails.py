"""register-job-definition-retry-attempts-above-maximum-fails."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "register-job-definition-retry-attempts-above-maximum-fails"
GROUP = 'overly-permissive'
SERVICES = ['batch']

# ===== helpers =====

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _swallow(fn):
    """Run a teardown step; any failure raises."""
    fn()


def _deregister_jd(bat, name, revision):
    _swallow(lambda: bat.deregister_job_definition(jobDefinition=f"{name}:{revision}"))


def _client_error(fn):
    """Call fn(); return (Error.Code, Error.Message, RequestId) of the ClientError it raises. An
    unexpected SUCCESS raises, so accepting input AWS refuses is never a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message"), exc.response.get("ResponseMetadata", {}).get("RequestId")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _describe_jd_revisions(bat, name, status=None):
    """All revisions of one job-definition NAME, ascending. status=None means ACTIVE-only."""
    kwargs = {"jobDefinitionName": name}
    if status:
        kwargs["status"] = status
    out, token = [], None
    while True:
        if token:
            kwargs["nextToken"] = token
        resp = bat.describe_job_definitions(**kwargs)
        out.extend(resp.get("jobDefinitions", []))
        token = resp.get("nextToken")
        if not token:
            break
    return sorted(out, key=lambda d: d["revision"])

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """retryStrategy.attempts is capped at 10: attempts=11 is refused and mints no revision.

    attempts=10 registers before and after the refusal and reads back through describe.
    """
    bat = ctx.client("batch")
    name = ctx.unique_name("sim2real-behav-jd-retrycap-")
    props = {
        "image": "public.ecr.aws/docker/library/busybox:1.36",
        "command": ["/bin/sh", "-c", "exit 0"],
        "resourceRequirements": [
            {"type": "VCPU", "value": "1"},
            {"type": "MEMORY", "value": "512"},
        ],
    }

    ok = bat.register_job_definition(
        jobDefinitionName=name,
        type="container",
        containerProperties=dict(props),
        retryStrategy={"attempts": 10},
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _deregister_jd(bat, name, ok["revision"]))
    assert ok["revision"] == 1, f"expected revision 1, got {ok['revision']}"
    rev1 = _describe_jd_revisions(bat, name)[0]
    assert rev1.get("retryStrategy", {}).get("attempts") == 10, (
        f"the boundary value 10 must be stored and echoed, got {rev1.get('retryStrategy')!r}"
    )

    # The model has no range trait on attempts, so botocore sends 11 and the service refuses it.
    code, message, request_id = _client_error(lambda: bat.register_job_definition(
        jobDefinitionName=name,
        type="container",
        containerProperties=dict(props),
        retryStrategy={"attempts": 11},
        tags=_MANAGED_TAGS,
    ))
    assert code == "ClientException", (
        f"retryStrategy.attempts=11 exceeds the documented maximum of 10 and must be rejected "
        f"with ClientException, got {code!r}"
    )
    expected = (
        "Error executing request, Exception : RetryAttempts must be between 1 and 10., "
        f"RequestId: {request_id}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    revs = [d["revision"] for d in _describe_jd_revisions(bat, name)]
    assert revs == [1], f"the rejected registration must not mint a revision; got {revs}"
    still = _describe_jd_revisions(bat, name)[0]
    assert still.get("retryStrategy", {}).get("attempts") == 10, (
        f"revision 1 must be unchanged by the rejected call, got {still.get('retryStrategy')!r}"
    )

    again = bat.register_job_definition(
        jobDefinitionName=name,
        type="container",
        containerProperties=dict(props),
        retryStrategy={"attempts": 10},
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _deregister_jd(bat, name, again["revision"]))
    assert again["revision"] == 2, f"expected the control registration to be revision 2, got {again['revision']}"

    final_revs = _describe_jd_revisions(bat, name)
    final_by_rev = {d["revision"]: d for d in final_revs}
    assert set(final_by_rev) == {1, 2}, f"expected exactly revisions {{1, 2}} ACTIVE, got {sorted(final_by_rev)}"
    assert final_by_rev[1].get("retryStrategy", {}).get("attempts") == 10, (
        f"revision 1 must still read back attempts=10 after the rejected call, "
        f"got {final_by_rev[1].get('retryStrategy')!r}"
    )
    assert final_by_rev[2].get("retryStrategy", {}).get("attempts") == 10, (
        f"revision 2 must read back attempts=10 through an independent describe, "
        f"got {final_by_rev[2].get('retryStrategy')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
