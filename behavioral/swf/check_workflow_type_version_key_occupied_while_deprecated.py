"""workflow-type-version-key-occupied-while-deprecated."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "workflow-type-version-key-occupied-while-deprecated"
GROUP = "negative-classes"
SERVICES = ["swf"]

_SHARED_DOMAIN = "sim2real-swf-shared"


def _shared_domain(ctx) -> str:
    """The account's shared SWF domain, registered if absent and never deprecated: SWF has no
    DeleteDomain, and a deprecated domain counts toward the registered-domain quota."""
    swf = ctx.client("swf")
    try:
        status = swf.describe_domain(name=_SHARED_DOMAIN)["domainInfo"]["status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "UnknownResourceFault":
            raise
        status = None
    try:
        if status is None:
            swf.register_domain(
                name=_SHARED_DOMAIN,
                workflowExecutionRetentionPeriodInDays="1",
                tags=[{"key": "sim2real:infra", "value": "swf-shared"}],
            )
        elif status == "DEPRECATED":
            swf.undeprecate_domain(name=_SHARED_DOMAIN)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DomainAlreadyExistsFault":
            raise
    return _SHARED_DOMAIN


def _delete_type(swf, domain: str, workflow_type: dict) -> None:
    """Teardown: deprecate then delete a workflow type; already deprecated or gone is fine."""
    try:
        swf.deprecate_workflow_type(domain=domain, workflowType=workflow_type)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("TypeDeprecatedFault", "UnknownResourceFault"):
            raise
    try:
        swf.delete_workflow_type(domain=domain, workflowType=workflow_type)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "UnknownResourceFault":
            raise


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises. An unexpected success raises, so an
    accepted call AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A deprecated workflow type's (name, version) key still refuses RegisterWorkflowType and
    Describe still reports its original defaults; a new version registers; deleting the
    deprecated version frees the key for a re-registration with its own new defaults."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)
    name = ctx.unique_name("sim2real-behav-wt-")

    original = {"name": name, "version": "1.0"}
    swf.register_workflow_type(
        domain=domain,
        name=name,
        version="1.0",
        defaultTaskList={"name": "sim2real-behav-tl-original"},
        defaultTaskStartToCloseTimeout="60",
        defaultExecutionStartToCloseTimeout="3600",
        defaultChildPolicy="TERMINATE",
    )
    ctx.on_cleanup(lambda: _delete_type(swf, domain, original))

    swf.deprecate_workflow_type(domain=domain, workflowType=original)

    deprecated = swf.describe_workflow_type(domain=domain, workflowType=original)
    assert deprecated["typeInfo"]["status"] == "DEPRECATED", deprecated["typeInfo"]
    cfg = deprecated["configuration"]
    assert cfg["defaultTaskList"]["name"] == "sim2real-behav-tl-original", cfg
    assert cfg["defaultTaskStartToCloseTimeout"] == "60", cfg
    assert cfg["defaultChildPolicy"] == "TERMINATE", cfg

    code, message = _error(
        lambda: swf.register_workflow_type(domain=domain, name=name, version="1.0")
    )
    assert code == "TypeAlreadyExistsFault", code
    assert message == f"WorkflowType=[name={name}, version=1.0]", message

    # Legal neighbour: a new version of the same name registers while the original stays deprecated.
    new_version = {"name": name, "version": "2.0"}
    swf.register_workflow_type(
        domain=domain,
        name=name,
        version="2.0",
        defaultTaskList={"name": "sim2real-behav-tl-v2"},
        defaultTaskStartToCloseTimeout="90",
        defaultExecutionStartToCloseTimeout="7200",
        defaultChildPolicy="ABANDON",
    )
    ctx.on_cleanup(lambda: _delete_type(swf, domain, new_version))

    v2 = swf.describe_workflow_type(domain=domain, workflowType=new_version)
    assert v2["typeInfo"]["status"] == "REGISTERED", v2["typeInfo"]
    v2_cfg = v2["configuration"]
    assert v2_cfg["defaultTaskList"]["name"] == "sim2real-behav-tl-v2", v2_cfg
    assert v2_cfg["defaultChildPolicy"] == "ABANDON", v2_cfg

    # Deleting the deprecated version releases its key.
    swf.delete_workflow_type(domain=domain, workflowType=original)
    gone_code, gone_message = _error(
        lambda: swf.describe_workflow_type(domain=domain, workflowType=original)
    )
    assert gone_code == "UnknownResourceFault", gone_code
    assert gone_message == f"Unknown type: WorkflowType=[name={name}, version=1.0]", gone_message

    # The released (name, version) key accepts a fresh registration with its own new defaults.
    swf.register_workflow_type(
        domain=domain,
        name=name,
        version="1.0",
        defaultTaskList={"name": "sim2real-behav-tl-reborn"},
        defaultTaskStartToCloseTimeout="120",
        defaultExecutionStartToCloseTimeout="10800",
        defaultChildPolicy="REQUEST_CANCEL",
    )
    ctx.on_cleanup(lambda: _delete_type(swf, domain, original))

    reborn = swf.describe_workflow_type(domain=domain, workflowType=original)
    assert reborn["typeInfo"]["status"] == "REGISTERED", reborn["typeInfo"]
    reborn_cfg = reborn["configuration"]
    assert reborn_cfg["defaultTaskList"]["name"] == "sim2real-behav-tl-reborn", reborn_cfg
    assert reborn_cfg["defaultChildPolicy"] == "REQUEST_CANCEL", reborn_cfg
    assert reborn_cfg["defaultExecutionStartToCloseTimeout"] == "10800", reborn_cfg


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
