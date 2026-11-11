"""secure-string-decrypts-on-batch-history-and-path-reads-and-leaves-them-after-delete."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "secure-string-decrypts-on-batch-history-and-path-reads-and-leaves-them-after-delete"
GROUP = "state-machine"
SERVICES = ["ssm"]


def _error(fn):
    """(Error.Code, HTTP status, Error.Message) of the ClientError fn raises; FAILS on success."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"), err.get(
            "Message"
        ) or ""
    raise AssertionError("the call succeeded; expected a refusal")


def _refusal(got, what):
    """(code, message) of an ``_error`` result, after grading its HTTP 4xx status."""
    code, status, message = got
    assert isinstance(status, int) and 400 <= status < 500, f"{what}: answered HTTP {status!r}, expected 4xx"
    return code, message


def _delete_if_present(ssm, name):
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise


def _settled(probe, done, timeout_s=30.0, interval_s=2.0):
    """probe() once done(answer) holds, or its last answer at the deadline (bounded read-only poll)."""
    deadline = time.monotonic() + timeout_s
    while True:
        got = probe()
        if done(got) or time.monotonic() >= deadline:
            return got
        time.sleep(interval_s)


def _by_path(ssm, path, decrypt):
    out = {}
    for page in ssm.get_paginator("get_parameters_by_path").paginate(Path=path, Recursive=True,
                                                                       WithDecryption=decrypt):
        out.update({p["Name"]: (p["Type"], p["Value"]) for p in page["Parameters"]})
    return out


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """WithDecryption=True returns a SecureString's plaintext on GetParameters, GetParametersByPath and
    each GetParameterHistory version, while a String sibling reads the same either way; after the
    delete the secret moves to InvalidParameters and leaves the path, and the sibling stays.
    """
    ssm = ctx.client("ssm")
    base = "/" + ctx.unique_name("sim2real-behav-secure-reads-")
    secret, plain = f"{base}/secret", f"{base}/plain"
    old_text, new_text = "old-" + ctx.unique_name("s"), "new-" + ctx.unique_name("s")
    ssm.put_parameter(Name=secret, Value=old_text, Type="SecureString")
    ctx.on_cleanup(lambda: _delete_if_present(ssm, secret))
    ssm.put_parameter(Name=secret, Value=new_text, Type="SecureString", Overwrite=True)
    ssm.put_parameter(Name=plain, Value="visible", Type="String")
    ctx.on_cleanup(lambda: _delete_if_present(ssm, plain))

    batch = ssm.get_parameters(Names=[secret, plain], WithDecryption=True)
    assert {p["Name"]: (p["Type"], p["Version"], p["Value"]) for p in batch["Parameters"]} == {
        secret: ("SecureString", 2, new_text),
        plain: ("String", 1, "visible"),
    }, f"GetParameters WithDecryption=True: got {batch['Parameters']!r}"
    assert batch["InvalidParameters"] == [], (
        f"GetParameters of two live names must report no InvalidParameters, got {batch['InvalidParameters']!r}"
    )
    raw = {p["Name"]: p["Value"] for p in ssm.get_parameters(Names=[secret, plain])["Parameters"]}
    assert raw[plain] == "visible" and raw[secret] and new_text not in raw[secret], (
        f"without decryption the String must read as stored and the SecureString must not: {raw!r}"
    )

    history = [
        (h["Version"], h["Value"])
        for page in ssm.get_paginator("get_parameter_history").paginate(Name=secret, WithDecryption=True)
        for h in page["Parameters"]
    ]
    assert sorted(history) == [(1, old_text), (2, new_text)], (
        f"GetParameterHistory WithDecryption=True must return each version's plaintext, got {history!r}"
    )
    assert _by_path(ssm, base, True) == {secret: ("SecureString", new_text), plain: ("String", "visible")}, (
        f"GetParametersByPath WithDecryption=True: got {_by_path(ssm, base, True)!r}"
    )
    undecrypted = _by_path(ssm, base, False)
    assert undecrypted[plain] == ("String", "visible") and new_text not in undecrypted[secret][1], (
        f"without decryption the path read must return the String as stored and the SecureString "
        f"encrypted, got types {[(n, t) for n, (t, _) in undecrypted.items()]!r}"
    )

    ssm.delete_parameter(Name=secret)
    after = _settled(
        lambda: ssm.get_parameters(Names=[secret, plain], WithDecryption=True),
        lambda r: r["InvalidParameters"] == [secret],
    )
    kept = [(p["Name"], p["Value"]) for p in after["Parameters"]]
    assert kept == [(plain, "visible")], f"after the delete only {plain} may resolve, got {kept!r}"
    assert after["InvalidParameters"] == [secret], f"InvalidParameters after the delete: {after['InvalidParameters']!r}"
    path_after = _settled(lambda: _by_path(ssm, base, True), lambda r: secret not in r)
    assert path_after == {plain: ("String", "visible")}, f"the deleted secret must leave the path, got {path_after!r}"
    got = _refusal(_error(lambda: ssm.get_parameter_history(Name=secret, WithDecryption=True)), "history")
    assert got == ("ParameterNotFound", ""), f"GetParameterHistory on the deleted secret: got {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
