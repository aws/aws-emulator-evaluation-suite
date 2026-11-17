"""deprecated-zeppelin-runtime-rejected-regardless-of-application-mode."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deprecated-zeppelin-runtime-rejected-regardless-of-application-mode"
GROUP = "rejected-configuration"
SERVICES = ["glue", "iam", "kinesisanalyticsv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateApplication refuses RuntimeEnvironment ZEPPELIN-FLINK-1_0 as deprecated whether or
    not ApplicationMode is INTERACTIVE, creating nothing either time, while the current
    ZEPPELIN-FLINK-3_0 runtime with INTERACTIVE settles READY over the same role.

    Reference: https://docs.aws.amazon.com/managed-flink/latest/apiv2/API_CreateApplication.html
    """
    kda = ctx.client("kinesisanalyticsv2")
    role = _studio_role(ctx)

    # Positive control FIRST: it also absorbs the fresh role's propagation window, so the
    # refusals below cannot be explained by the role not yet being assumable.
    db = _glue_db(ctx)
    current = ctx.unique_name("sim2real-dep-flk-")
    created = _create_app(
        ctx, ApplicationName=current, RuntimeEnvironment=_CURRENT_RUNTIME,
        ApplicationMode="INTERACTIVE", ServiceExecutionRole=role,
        ApplicationConfiguration={"ZeppelinApplicationConfiguration": {
            "CatalogConfiguration": _catalog(ctx, db)}},
    )
    assert created["ApplicationName"] == current, (
        f"CreateApplication answered for {created['ApplicationName']!r}, not {current!r}"
    )
    detail = _poll(lambda: _describe(ctx, current), lambda d: d["ApplicationStatus"] == "READY",
                   timeout_s=120.0, interval_s=3.0, description=f"{current} settles READY")
    assert detail["RuntimeEnvironment"] == _CURRENT_RUNTIME, (
        f"declared {_CURRENT_RUNTIME!r}, DescribeApplication reports "
        f"{detail['RuntimeEnvironment']!r}"
    )
    assert detail["ApplicationMode"] == "INTERACTIVE", (
        f"declared INTERACTIVE, DescribeApplication reports {detail.get('ApplicationMode')!r}"
    )

    unset = ctx.unique_name("sim2real-dep-flk-")
    expect_error(
        lambda: kda.create_application(ApplicationName=unset, RuntimeEnvironment=_DEPRECATED_RUNTIME,
                                        ServiceExecutionRole=role),
        *_DEPRECATED,
        undo=lambda detail: ctx.on_cleanup(lambda: _delete_app(ctx, unset)),
    )
    got = _error(lambda: kda.describe_application(ApplicationName=unset))
    want = ("ResourceNotFoundException", f"Application '{unset}' does not exist.")
    assert got == want, (
        f"DescribeApplication for the refused mode-less deprecated-runtime create {unset!r} "
        f"answered {got!r}, expected {want!r}"
    )

    interactive = ctx.unique_name("sim2real-dep-flk-")
    expect_error(
        lambda: kda.create_application(ApplicationName=interactive,
                                        RuntimeEnvironment=_DEPRECATED_RUNTIME,
                                        ApplicationMode="INTERACTIVE", ServiceExecutionRole=role),
        *_DEPRECATED,
        undo=lambda detail: ctx.on_cleanup(lambda: _delete_app(ctx, interactive)),
    )
    got = _error(lambda: kda.describe_application(ApplicationName=interactive))
    want = ("ResourceNotFoundException", f"Application '{interactive}' does not exist.")
    assert got == want, (
        f"DescribeApplication for the refused INTERACTIVE deprecated-runtime create "
        f"{interactive!r} answered {got!r}, expected {want!r}"
    )


#: The trust policy a Studio notebook's execution role needs.
_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "kinesisanalytics.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})

#: The inline policy (`studio-access`) granting the role access to the services it drives.
_STUDIO_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["kinesis:*", "glue:*", "s3:*", "logs:*", "cloudwatch:*"],
        "Resource": "*",
    }],
})

#: The withdrawn Studio runtime generation this check refuses.
_DEPRECATED_RUNTIME = "ZEPPELIN-FLINK-1_0"

#: The current Studio runtime generation this check's positive control creates.
_CURRENT_RUNTIME = "ZEPPELIN-FLINK-3_0"

#: The exact refusal a withdrawn Studio runtime generation draws, regardless of ApplicationMode.
_DEPRECATED = (
    "InvalidArgumentException",
    "Runtime ZEPPELIN-FLINK-1_0 is deprecated. Please choose a valid version from: "
    "https://docs.aws.amazon.com/managed-flink/latest/apiv2/API_CreateApplication.html"
    "#APIReference-CreateApplication-request-RuntimeEnvironment",
)

#: Bound on the IAM-propagation retry around CreateApplication. No API reports when a fresh role
#: becomes assumable by the service, so the refusal itself is retried, and nothing else is.
_ASSUME_DEADLINE_S = 120
#: Bound on an application leaving DescribeApplication after DeleteApplication.
_DELETE_DEADLINE_S = 180


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}"[:900])


def _error(fn) -> tuple[str, str]:
    """The AWS (code, message) fn() raises.

    Raises when the call SUCCEEDS instead of returning a falsy sentinel.
    """
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"the call succeeded where real AWS rejects it: {result!r}"[:600])


def _poll(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) holds; return the result, or fail quoting the last one."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s; last: {last!r}"[:900])
        time.sleep(interval_s)


def _studio_role(ctx) -> str:
    """The notebook's execution role, with its cleanup registered."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-dep-flk-role-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=_TRUST,
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    iam.put_role_policy(RoleName=name, PolicyName="studio-access", PolicyDocument=_STUDIO_POLICY)
    return arn


def _delete_role(ctx, name: str) -> None:
    iam = ctx.client("iam")
    for pol in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=name, PolicyName=pol)
    iam.delete_role(RoleName=name)


def _create_app(ctx, **kwargs) -> dict:
    """CreateApplication, retrying ONLY the fresh-role refusal, and registering the delete.

    A role created seconds earlier is not yet assumable by the service, which answers
    `InvalidArgumentException: ... sufficient privileges to assume the role`. A bounded retry of
    that one refusal is the correct handling; everything else raises immediately. The delete is
    registered as soon as the create returns, before any assertion can abort the check.
    """
    kda = ctx.client("kinesisanalyticsv2")
    deadline = time.monotonic() + _ASSUME_DEADLINE_S
    while True:
        try:
            detail = kda.create_application(
                Tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs)["ApplicationDetail"]
        except ClientError as exc:
            if "assume the role" not in str(exc) or time.monotonic() >= deadline:
                raise
            time.sleep(5)
            continue
        ctx.on_cleanup(lambda n=kwargs["ApplicationName"]: _delete_app(ctx, n))
        return detail


def _app_gone(ctx, name: str) -> bool:
    try:
        ctx.client("kinesisanalyticsv2").describe_application(ApplicationName=name)
    except ClientError as exc:
        return exc.response["Error"]["Code"] == "ResourceNotFoundException"
    return False


def _delete_app(ctx, name: str) -> None:
    """Delete the application and wait for DescribeApplication to stop answering."""
    kda = ctx.client("kinesisanalyticsv2")
    try:
        detail = kda.describe_application(ApplicationName=name)["ApplicationDetail"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    if detail["ApplicationStatus"] != "DELETING":
        kda.delete_application(ApplicationName=name, CreateTimestamp=detail["CreateTimestamp"])
    deadline = time.monotonic() + _DELETE_DEADLINE_S
    while True:
        if _app_gone(ctx, name):
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"application {name} still described after {_DELETE_DEADLINE_S}s")
        time.sleep(3)


def _glue_db(ctx) -> str:
    """A Glue database under a minted name, with its delete registered. Returns the name."""
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real_dep_flk_db_")
    glue.create_database(DatabaseInput={"Name": name, "Description": "sim2real flink studio"},
                         Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: ctx.client("glue").delete_database(Name=name))
    return name


def _db_arn(ctx, name: str) -> str:
    """The database ARN, composed from the target's own identity."""
    return f"arn:aws:glue:{ctx.region}:{ctx.account}:database/{name}"


def _catalog(ctx, db: str) -> dict:
    """The CatalogConfiguration block a Studio notebook declares. A Studio notebook REQUIRES a
    resolvable Glue database: with the block omitted, CreateApplication resolves the database
    named `default`, so a check that omitted it would depend on whether this account happens to
    hold one."""
    return {"GlueDataCatalogConfiguration": {"DatabaseARN": _db_arn(ctx, db)}}


def _describe(ctx, name: str) -> dict:
    return ctx.client("kinesisanalyticsv2").describe_application(ApplicationName=name)[
        "ApplicationDetail"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
