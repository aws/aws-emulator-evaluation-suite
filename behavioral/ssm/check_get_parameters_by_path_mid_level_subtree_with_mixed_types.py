"""get-parameters-by-path-mid-level-subtree-with-mixed-types."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-parameters-by-path-mid-level-subtree-with-mixed-types"
GROUP = 'state-machine'
SERVICES = ['ssm']


def _delete_if_present(ssm, name):
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise


def _by_path(ssm, path, recursive, decrypt=False):
    out = {}
    for page in ssm.get_paginator("get_parameters_by_path").paginate(
        Path=path, Recursive=recursive, WithDecryption=decrypt
    ):
        out.update({p["Name"]: (p["Type"], p["Value"]) for p in page["Parameters"]})
    return out


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetParametersByPath on a mid-level node of a four-level tree returns its descendants of
    every type at every depth, excludes the node's own parameter, its parent's other children and
    a prefix-sharing sibling, and Recursive=False keeps only the node's direct children.
    """
    ssm = ctx.client("ssm")
    root = "/" + ctx.unique_name("sim2real-behav-midpath-")
    node = f"{root}/svc"
    tree = {
        node: ("String", "the-node-itself"),
        f"{node}/zone": ("String", "zone-a"),
        f"{node}/hosts": ("StringList", "a.example.com,b.example.com"),
        f"{node}/db/password": ("SecureString", "pw-" + ctx.unique_name("p")),
        f"{node}/db/replica/port": ("String", "5433"),
        f"{root}/other": ("String", "parent-sibling"),
        f"{root}/svcx/decoy": ("String", "prefix-decoy"),
        f"{root}/sv": ("String", "short-decoy"),
    }
    for name, (kind, value) in tree.items():
        ssm.put_parameter(Name=name, Value=value, Type=kind)
        ctx.on_cleanup(lambda n=name: _delete_if_present(ssm, n))

    below = {n: tv for n, tv in tree.items() if n.startswith(node + "/")}
    decrypted = _by_path(ssm, node, recursive=True, decrypt=True)
    assert decrypted == below, (
        f"recursive WithDecryption under {node} must return exactly its four descendants with their "
        f"types and values, got {sorted(decrypted)}"
    )
    raw = _by_path(ssm, node, recursive=True)
    secret = f"{node}/db/password"
    assert set(raw) == set(below) and raw[secret][0] == "SecureString" and raw[secret][1] != tree[secret][1], (
        f"without decryption the same four names return and the SecureString stays encrypted, got {raw!r}"
    )
    plain_want = {n: v for n, v in below.items() if n != secret}
    plain_got = {n: v for n, v in raw.items() if n != secret}
    assert plain_got == plain_want, f"the non-secret descendants must read as stored: expected {plain_want!r}, got {plain_got!r}"

    one_level = _by_path(ssm, node, recursive=False)
    assert one_level == {n: below[n] for n in (f"{node}/zone", f"{node}/hosts")}, (
        f"Recursive=False under {node} must return only its two direct children, got {one_level!r}"
    )
    deeper = _by_path(ssm, f"{node}/db", recursive=False)
    assert set(deeper) == {secret}, f"Recursive=False under {node}/db must return only {secret}, got {sorted(deeper)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
