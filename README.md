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

The programme's landing page — including the published log list — is at
**[witnessplz.transparency.goog](https://witnessplz.transparency.goog/)**. It is
built from `site/` and deployed to GitHub Pages on every push to `main`.

> [!NOTE]
> This programme is separate from the
> [Public Witness Network](https://witness-network.org/). Witnesses here make a
> service availability commitment to Google and are onboarded only by agreement
> with Google; the published log list is not an open invitation to begin
> cosigning Google's logs.

## For log owners

To publish a new log origin:

1. Create a directory under `logs/<product>/` with one or more log-list files
   (e.g. `log-list.txt`) following the
   [log-list format](https://github.com/transparency-dev/witness-network/blob/main/log-list-format.md).
2. Add a `BUILD.bazel` that exports those files (`exports_files([...])`) and
   declares a `log_list_test()` over them.
3. Add your log-list to the `concatenated_log_list()` target in
   `logs/BUILD.bazel`, and refresh the checked-in combined list (see below).
4. Create whatever `tlog_policy_pair()` targets your product needs under
   `policies/<product>/`.
5. Submit a pull request.

## For witness operators

Witness operators join this programme by agreement with Google, rather than by
open enrolment. If you operate a witness and are interested in taking part,
please [open an issue](https://github.com/google/google-tlog-witness/issues/new)
first.

Once an agreement is in place, to add or update a witness:

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

The rules enforced by `//witnesses:witnesses_test` are:

- Each file must define at least one `witness` line.
- The `<url>` field is required, and the `<vkey>` field must follow the
  `<name>+<keyid>+<key>` format.
- Witness and group names must be unique within a file, and group members must
  reference names defined earlier in the same file.
- `log` and `quorum` lines are not permitted in witness files — those are
  policy-assembly decisions made by `tlog_policy()` callers.

## For tlog-policy consumers

Policies live under `policies/<product>/`. A `tlog_policy_pair()` produces two
policies from shared inputs, one for each consumer camp:

- **Log policy** — consumed by the log operator to know which witnesses to
  contact for cosigning.
- **Verifier policy** — consumed by verifiers to know what witness
  cosignatures to require on checkpoints.

How many pairs a product needs, and how they are named, is up to that product.
PAIC, for instance, keeps separate prod and dev pairs in `//policies/paic/`:

```bash
bazel build //policies/paic/...  # builds prod-{log,verifier} and dev-{log,verifier}
```

Each target produces a `.policy` file named after it, e.g.
`//policies/paic:prod-log` produces `prod-log.policy`.

The combined log list for witnesses is checked in at
`logs/log-list-10qps-10klogs.txt` so that it is served over HTTPS at:

```
https://witnessplz.transparency.goog/log-list-10qps-10klogs.txt
https://raw.githubusercontent.com/google/google-tlog-witness/main/logs/log-list-10qps-10klogs.txt
```

When the source log lists change, update the checked-in copy by running:

```bash
bazel run //logs:copy_generated_10qps-10klogs_list
```

The `//logs:copy_generated_10qps-10klogs_list_test` test will fail if the
checked-in file falls out of sync with the generated output.

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
  a single combined log list, written to `<name>.txt`.
- `tlog_policy(name, log_lists, witnesses, quorum, groups=[])` — generates a
  single tlog-policy file (`<name>.policy`) from log lists, witness configs, and
  a caller-defined quorum rule. It also creates a `<name>.policy-test` target
  that validates the generated policy.
- `tlog_policy_pair(name, log_lists, witnesses, quorum, verifier_quorum=None,
  groups=[])` — generates a matched pair of log and verifier tlog-policy files
  from shared inputs, via two `tlog_policy()` targets named `<name>-log` and
  `<name>-verifier`. An optional `verifier_quorum` allows the verifier quorum to
  diverge temporarily during a policy rollout.
- `log_list_test(name, srcs)` — validates log-list files against the logs/v0
  format.
- `tlog_policy_test(name, srcs)` — validates tlog-policy files against the
  [C2SP spec](https://c2sp.org/tlog-policy).
