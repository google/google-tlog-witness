"""Bazel macros for assembling transparency log lists and tlog-policy files."""

load("@rules_go//go:def.bzl", "go_test")

def concatenated_log_list(name, srcs, visibility = None):
    """Concatenates per-product log lists into a single combined log list.

    The output file is named <name>.txt and follows the witness-network
    log-list format:
    https://github.com/transparency-dev/witness-network/blob/main/log-list-format.md

    Args:
        name: Target name. The output file will be <name>.txt.
        srcs: List of per-product log-list file labels.
        visibility: Standard Bazel visibility.
    """
    native.genrule(
        name = name,
        srcs = srcs,
        outs = [name + ".txt"],
        cmd = "$(location //tools:gen_log_list) " +
              " ".join(["--input=$(location %s)" % s for s in srcs]) +
              " --output=$@",
        tools = ["//tools:gen_log_list"],
        visibility = visibility,
    )

def tlog_policy(name, log_lists, witnesses, quorum, groups = [], visibility = None):
    """Generates a tlog-policy file.

    Assembles a tlog-policy by directly inlining its inputs. Each input
    section is preceded by a header comment indicating the source file.
    The final section contains any additional groups and the quorum rule,
    which come from the BUILD rule.

    Spec: https://github.com/C2SP/C2SP/pull/233
    TODO: update the link above when the C2SP PR is merged.

    Args:
        name: Target name. The output file will be <name>.txt.
        log_lists: List of log-list file labels. All vkeys are extracted
            and emitted as "log" lines.
        witnesses: List of witness config file labels. Contents are
            inlined verbatim (including comments).
        groups: Optional list of additional group definition strings, e.g.
            ["group all-witnesses any w1 w2"]. These are appended after
            the witness sections and may reference names defined in
            witness files.
        quorum: The quorum name (without the "quorum " prefix), e.g.
            "ring-any-bells" or "none".
        visibility: Standard Bazel visibility.
    """
    cmd_parts = ["$(location //tools:gen_tlog_policy)"]
    for l in log_lists:
        cmd_parts.append("--log-list=$(location %s)" % l)
    for w in witnesses:
        cmd_parts.append("--witnesses=$(location %s)" % w)
    for g in groups:
        g_normalized = g if g.startswith("group ") else "group " + g
        cmd_parts.append("--group=\"%s\"" % g_normalized)
    cmd_parts.append("--quorum=%s" % quorum)
    cmd_parts.append("> $@")

    native.genrule(
        name = name,
        srcs = log_lists + witnesses,
        outs = [name + ".txt"],
        cmd = " ".join(cmd_parts),
        tools = ["//tools:gen_tlog_policy"],
        visibility = visibility,
    )

def tlog_policy_pair(name, log_lists, witnesses, quorum, verifier_quorum = None, groups = [], visibility = None):
    """Generates a matched pair of log and verifier tlog-policy files.

    Produces two tlog-policy targets from shared inputs, ensuring that the
    log lists and witness configurations are always identical between the
    log and verifier policies. Only the quorum configuration may differ,
    and only temporarily during a rollout (see "Policy rollout" in
    README.md).

    Args:
        name: Base target name. Generates <name>-log-tlog-policy and
            <name>-verifier-tlog-policy targets.
        log_lists: List of log-list file labels (shared by both policies).
        witnesses: List of witness config file labels (shared by both
            policies).
        quorum: The quorum name for the log policy (and the verifier
            policy, unless verifier_quorum is set).
        verifier_quorum: Optional. If set, the verifier policy uses this
            quorum instead of quorum. Use this during policy rollouts
            when the verifier quorum must temporarily diverge from the
            log quorum.
        groups: Optional list of additional group definition strings.
        visibility: Standard Bazel visibility.
    """
    tlog_policy(
        name = name + "-log-tlog-policy",
        log_lists = log_lists,
        witnesses = witnesses,
        quorum = quorum,
        groups = groups,
        visibility = visibility,
    )
    tlog_policy(
        name = name + "-verifier-tlog-policy",
        log_lists = log_lists,
        witnesses = witnesses,
        quorum = verifier_quorum or quorum,
        groups = groups,
        visibility = visibility,
    )

def log_list_test(name, srcs, **kwargs):
    """Validates log-list files against the logs/v0 format.

    Creates a go_test target that checks each file in srcs conforms to the
    witness-network log-list format:
    https://github.com/transparency-dev/witness-network/blob/main/log-list-format.md

    Args:
        name: Target name for the test.
        srcs: List of log-list file labels (typically a glob expression).
        **kwargs: Additional arguments passed to go_test (e.g. tags, size).
    """
    go_test(
        name = name,
        srcs = ["//build_defs:log_list_files_test.go"],
        data = srcs,
        deps = ["//internal/vkey"],
        **kwargs
    )

