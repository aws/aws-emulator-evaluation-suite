"""register-job-definition-missing-container-properties-fails."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "register-job-definition-missing-container-properties-fails"
GROUP = 'error-semantics'
SERVICES = ['batch']

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _client_error(fn):
    """Call fn(); return (Error.Code, Error.Message, RequestId) of the ClientError it raises.
    An unexpected SUCCESS raises, so an emulator that accepts what AWS refuses fails loudly
    instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message"), exc.response.get("ResponseMetadata", {}).get("RequestId")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _deregister_jd(bat, name, revision):
    bat.deregister_job_definition(jobDefinition=f"{name}:{revision}")


def _describe_jd_revisions(bat, name):
    """All ACTIVE revisions of one job-definition NAME, ascending."""
    out, token = [], None
    kwargs = {"jobDefinitionName": name}
    while True:
        if token:
            kwargs["nextToken"] = token
        resp = bat.describe_job_definitions(**kwargs)
        out.extend(resp.get("jobDefinitions", []))
        token = resp.get("nextToken")
        if not token:
            break
    return sorted(out, key=lambda d: d["revision"])


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """type=container without containerProperties is rejected at registration time: no
    revision is minted by the rejected call, and a definition carrying the required
    containerProperties still registers cleanly both before and after.
    """
    bat = ctx.client("batch")
    name = ctx.unique_name("sim2real-behav-jd-nocontainer-")
    props = {
        "image": "public.ecr.aws/docker/library/busybox:1.36",
        "command": ["/bin/sh", "-c", "exit 0"],
        "resourceRequirements": [
            {"type": "VCPU", "value": "1"},
            {"type": "MEMORY", "value": "512"},
        ],
    }

    # Positive control: a full type=container definition registers cleanly.
    ok = bat.register_job_definition(
        jobDefinitionName=name,
        type="container",
        containerProperties=dict(props),
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _deregister_jd(bat, name, ok["revision"]))
    assert ok["revision"] == 1, f"expected revision 1, got {ok['revision']}"

    # Break exactly one thing: omit containerProperties.
    code, message, request_id = _client_error(lambda: bat.register_job_definition(
        jobDefinitionName=name,
        type="container",
    ))
    assert code == "ClientException", f"expected ClientException for missing containerProperties, got {code!r}"
    expected = (
        "Error executing request, Exception : ECS ContainerProperties, ecsProperties, or eksProperties "
        f"is required when using type container., RequestId: {request_id}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The effect must be absent: the rejected call must not mint revision 2.
    revs = [d["revision"] for d in _describe_jd_revisions(bat, name)]
    assert revs == [1], f"the rejected registration must not mint a revision; got {revs}"

    # The control case still works: a subsequent valid registration still succeeds.
    again = bat.register_job_definition(
        jobDefinitionName=name,
        type="container",
        containerProperties=dict(props),
        tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _deregister_jd(bat, name, again["revision"]))
    assert again["revision"] == 2, f"expected the control registration to be revision 2, got {again['revision']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
