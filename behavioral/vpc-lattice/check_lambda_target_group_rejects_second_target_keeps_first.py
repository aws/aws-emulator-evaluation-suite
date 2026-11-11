"""lambda-target-group-rejects-second-target-keeps-first."""
from __future__ import annotations

import base64
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-target-group-rejects-second-target-keeps-first"
GROUP = 'target-registration'
SERVICES = ['vpc-lattice']

_ZIP_B64 = (
    "UEsDBBQAAAAAAAWeW123g1YTKwAAACsAAAAIAAAAaW5kZXgucHlkZWYgaGFuZGxlcihldmVudCwgY29udGV4dCk6CiAg"
    "ICByZXR1cm4ge30KUEsBAhQDFAAAAAAABZ5bXbeDVhMrAAAAKwAAAAgAAAAAAAAAAAAAAIABAAAAAGluZGV4LnB5UEsFBgAAAAABAAEANgAAAFEAAAAAAA=="
)


def _error(fn):
    """The AWS (code, message) ``fn()`` raised; raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("concern:representation", "concern:negative-classes", "axis:rejection", "cap:c1", "plane:control")
def run(ctx) -> None:
    """A LAMBDA target group holds at most one target: re-registering the same function is a
    no-op, but registering a second distinct function is refused and the first target survives
    untouched in ListTargets.
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    vl = ctx.client("vpc-lattice")

    role_name = ctx.unique_name("sim2real-latt-ltg-role-")
    trust = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)
    ctx.on_cleanup(lambda n=role_name: iam.delete_role(RoleName=n))
    role_arn = role["Role"]["Arn"]

    code = base64.b64decode(_ZIP_B64)
    fn1_name = ctx.unique_name("sim2real-latt-ltg-fn1-")
    fn2_name = ctx.unique_name("sim2real-latt-ltg-fn2-")

    # IAM role propagation to Lambda exposes no condition to poll, so this is a bounded retry
    # rather than a wait on an observable state.
    deadline = time.time() + 60
    fn1 = None
    while fn1 is None:
        try:
            fn1 = lam.create_function(
                FunctionName=fn1_name, Runtime="python3.12", Role=role_arn,
                Handler="index.handler", Code={"ZipFile": code}, Timeout=5,
            )
        except ClientError:
            if time.time() >= deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda n=fn1_name: lam.delete_function(FunctionName=n))

    fn2 = lam.create_function(
        FunctionName=fn2_name, Runtime="python3.12", Role=role_arn,
        Handler="index.handler", Code={"ZipFile": code}, Timeout=5,
    )
    ctx.on_cleanup(lambda n=fn2_name: lam.delete_function(FunctionName=n))

    tg = vl.create_target_group(name=ctx.unique_name("sim2real-latt-ltg-tg-"), type="LAMBDA")
    ctx.on_cleanup(lambda i=tg["id"]: vl.delete_target_group(targetGroupIdentifier=i))

    deadline = time.time() + 120
    while True:
        status = vl.get_target_group(targetGroupIdentifier=tg["id"])["status"]
        if status == "ACTIVE":
            break
        assert status == "CREATE_IN_PROGRESS" and time.time() < deadline, (
            f"target group {tg['id']} never reached ACTIVE: status={status!r}"
        )
        time.sleep(3)

    first = vl.register_targets(targetGroupIdentifier=tg["id"], targets=[{"id": fn1["FunctionArn"]}])
    ctx.on_cleanup(
        lambda i=tg["id"], a=fn1["FunctionArn"]: vl.deregister_targets(
            targetGroupIdentifier=i, targets=[{"id": a}]
        )
    )
    assert {t["id"] for t in first["successful"]} == {fn1["FunctionArn"]}, (
        f"registering the first target gave successful={first['successful']!r}"
    )

    repeat = vl.register_targets(targetGroupIdentifier=tg["id"], targets=[{"id": fn1["FunctionArn"]}])
    assert {t["id"] for t in repeat["successful"]} == {fn1["FunctionArn"]}, (
        f"re-registering the SAME already-registered target gave {repeat!r}, expected it to "
        f"succeed as a no-op rather than be refused as 'over capacity'"
    )

    error = _error(
        lambda: vl.register_targets(targetGroupIdentifier=tg["id"], targets=[{"id": fn2["FunctionArn"]}])
    )
    expected_error = (
        "ValidationException",
        f"Target group {tg['id']} with type LAMBDA can only contain a maximum of 1 targets",
    )
    assert error == expected_error, (
        f"registering a SECOND, distinct target on a LAMBDA target group raised {error!r}, "
        f"expected {expected_error!r}"
    )

    items = vl.list_targets(targetGroupIdentifier=tg["id"])["items"]
    ids = {i["id"] for i in items}
    assert ids == {fn1["FunctionArn"]}, (
        f"after the refused second registration, ListTargets reports {ids!r}; it must still hold "
        f"exactly the first target {fn1['FunctionArn']!r} and nothing from the refused call"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
