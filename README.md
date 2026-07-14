# google-tlog-witness

This repository is the canonical source of truth for Google's transparency log
witness interactions. It contains:

- **Log lists**: The set of Google-operated transparency log origins published
  for witness discovery, following the
  [log-list format](https://github.com/transparency-dev/witness-network/blob/main/log-list-format.md).
- **Witness configurations**: Endpoints and keys for witnesses that cosign
  Google's log checkpoints, following the
  [tlog-policy format](https://c2sp.org/tlog-policy).
- **tlog-policy files**: Generated policy files consumed by log operators and
  verifiers.

## For log owners

To publish a new log origin:

1. Create a directory under `logs/<product>/` with a `log-list.txt` file
   following the
   [log-list format](https://github.com/transparency-dev/witness-network/blob/main/log-list-format.md).
2. Add a `BUILD.bazel` with `exports_files(["log-list.txt"])`.
3. Add your log-list to the combined list target in the root `BUILD.bazel`.
4. Create `tlog_policy()` targets for your product under `policies/<product>/`.
5. Submit a pull request.

## For witness operators

To add or update a witness:

1. Create or edit `witnesses/<your-operator-name>.txt`.
2. Add `witness` lines for each endpoint.  Optionally add `group` lines to
   define operator-level groupings that tlog-policy authors can reference.
3. Submit a pull request; a Google engineer will review and merge.

### Witness file format

Witness files use a subset of the tlog-policy line types:

```
# Comments start with '#'; blank lines are ignored.
witness <name> <vkey> <url>
group <name> <threshold|any|all> <member>...
```

`log` and `quorum` lines are not permitted in witness files — those are
policy-assembly decisions made by `tlog_policy()` callers.

## For tlog-policy consumers

Each product typically defines two tlog-policy targets under
`policies/<product>/`, one for each consumer camp:

- **Log policy** — consumed by the log operator to know which witnesses to
  contact for cosigning.
- **Verifier policy** — consumed by verifiers to know what witness
  cosignatures to require on checkpoints.

For example, PAIC's policies live in `//policies/paic/` and can be built with:

```bash
bazel build //policies/paic/...  # builds prod-{log,verifier}-tlog-policy and dev-{log,verifier}-tlog-policy
```

The combined log list for witnesses is also available:

```bash
bazel build //:log-list-10qps-10klogs
```

## Policy rollout

Changes to the witness set — adding a witness, removing one, rotating a key, or
updating a URL — require coordinated updates to the log and verifier policies.
Each policy contains both a set of known witnesses and a quorum configuration;
the two policies are consumed by different parties (log operators and verifiers,
respectively) and cannot be updated atomically.

The core invariant is: at no point should a verifier demand a cosignature the
log cannot produce, nor should the log be unable to meet its own quorum. Because
each policy has its own quorum configuration, the rollout involves up to three
policy changes, each separated by a baking period:

1. If needed, **relax the verifier quorum** so it can be satisfied by whichever
   witness set is weaker — the current set or the target set. Wait until all
   production verifiers have been updated to use the relaxed policy.
2. **Update the log policy** — both the witness set (who to contact) and the
   log quorum — to the target state. Wait until the production log is operating
   under the new policy and any offline data consumed by verifiers (such as
   `tlog-proofs`) has been accordingly updated to match the new policy.
3. If needed, **tighten or clean up the verifier quorum** to the target state.

The specific scenarios below are all instances of this pattern.

**Adding a witness.** The verifier quorum already tolerates the current (weaker)
witness set, so step 1 is a no-op. The log policy is updated to contact the new
witness and to adjust the log quorum accordingly. Once the log is reliably
producing the new cosignatures, the verifier quorum can be tightened to require
them.

**Removing a witness.** The verifier quorum is relaxed first so that it can be
satisfied without the departing witness. Once that has baked, the log policy is
updated to stop contacting the witness and to adjust the log quorum to match.
The departing witness can then be cleaned out of the verifier policy entirely.

**Rotating a witness key.** This is effectively an overlapping add-then-remove.
The verifier quorum is updated first to accept cosignatures from either the old
or the new key. Once that has baked, the log policy is updated to use the new
key exclusively (both witness set and log quorum). After the log is reliably
producing cosignatures with the new key, the verifier policy is cleaned up to
remove the old key.

**Updating a witness URL.** Only the log policy needs to change, since the URL
is an operational detail used by the log to contact the witness. Verifier
policies are unaffected because they identify witnesses by key, not by URL.

## Building

This repository uses [Bazel](https://bazel.build/). Build all targets:

```bash
bazel build //...
```

The Bazel macros in `build_defs/tlog.bzl` provide:

- `concatenated_log_list(name, srcs)` — concatenates per-product log lists into
  a single combined log list.
- `tlog_policy(name, log_lists, witnesses, quorum, groups=[])` — generates a
  single tlog-policy file from log lists, witness configs, and a caller-defined
  quorum rule.
- `tlog_policy_pair(name, log_lists, witnesses, quorum, verifier_quorum=None,
  groups=[])` — generates a matched pair of log and verifier tlog-policy files
  (`<name>-log-tlog-policy` and `<name>-verifier-tlog-policy`) from shared
  inputs. An optional `verifier_quorum` allows the verifier quorum to diverge
  temporarily during a policy rollout.
- `log_list_test(name, srcs)` — validates log-list files against the logs/v0
  format.
- `tlog_policy_test(name, srcs)` — validates tlog-policy files against the
  [C2SP spec](https://c2sp.org/tlog-policy).
