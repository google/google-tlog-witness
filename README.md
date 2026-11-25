# google-tlog-witness

This repository is the canonical source of truth for Google's transparency log
witness interactions. It contains:

- **Log lists**: The set of Google-operated transparency log origins published
  for witness discovery, following the
  [tlog-list format](https://c2sp.org/tlog-list).
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
   [tlog-list format](https://c2sp.org/tlog-list).
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

Witness files use the `witness` and `group` lines from the tlog-policy format,
plus `group-log` and `group-verifier` for role-specific group definitions:

```
# Comments start with '#'; blank lines are ignored.
witness <name> <vkey> <url>
group <name> <threshold|any|all> <member>...
group-log <name> <threshold|any|all> <member>...
group-verifier <name> <threshold|any|all> <member>...
```

A `group-log` and a `group-verifier` line sharing a name define one group
differently for the two kinds of policy: the log policy gets the `group-log`
definition and the verifier policy gets the `group-verifier` one, each written
out as an ordinary `group` line. This lets a witness operator rotate keys by
editing only their own witness file; see
[Rotating a witness key](#rotating-a-witness-key).

The rules enforced by `//witnesses:witnesses_test` are:

- Each file must define at least one `witness` line.
- The `<url>` field is required, and the `<vkey>` field must follow the
  `<name>+<keyid>+<key>` format.
- Witness and group names must be unique within a file, and group members must
  reference names defined earlier in the same file.
- A name defined by `group-log` must also be defined by `group-verifier`, and
  vice versa, with exactly one line of each. The name can be used as a group
  member only after both lines.
- `log` and `quorum` lines are not permitted in witness files — those are
  policy-assembly decisions made by the callers of `tlog_log_policy()` and
  `tlog_verifier_policy()`.

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

### Witness list

`//witnesses:all-witnesses-log` collects every witness and group defined in
`witnesses/*.txt`, as a log sees them, into a single file
(`all-witnesses-log.txt`):

```bash
bazel build //witnesses:all-witnesses-log
```

The output is itself a witness config file containing only `witness` and
`group` lines (with `group-log` / `group-verifier` pairs resolved for the
`log` role). It is not a tlog-policy: it has no `log` lines and no `quorum`
line. To read it with a standard tlog-policy parser (such as
`github.com/transparency-dev/formats/policy`), append a `quorum none` line
before parsing.

This list lets software that runs a log check its policy — at start-up or in
a test — against the repository's canonical definitions. Because a product's
policy may define its own groups, it could by mistake or on purpose reuse a
name from `witnesses/` for different witnesses. Checking against the list
ensures that any name appearing in both has the same key and URL (for a
witness) or the same threshold and members (for a group), which matters when
monitoring pools results from several logs by witness or group name. This
repository only publishes the list; consumers perform the comparison.

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

### Rotating a witness key

Rotating a key is an overlapping add-then-remove. Express both policies in the
witness file with a `group-log` and `group-verifier` pair so product policies
pick the change up without being edited.

Once the witness is returning cosignatures from both its old and new keys, add
the new key so the log requires both while verifiers accept either:

```
witness example-old <vkey> https://witness.example
witness example-new <vkey> https://witness.example
group-log      example all example-old example-new
group-verifier example any example-old example-new
```

After the log is publishing both cosignatures and verifiers no longer hold
proofs cosigned only with the old key, remove `example-old` and collapse the
pair back to a single `group` line:

```
witness example-new <vkey> https://witness.example
group example any example-new
```

**Updating a witness URL.** Only the log policy needs to change, since the URL
is an operational detail used by the log to contact the witness. Verifier
policies are unaffected because they identify witnesses by key, not by URL.

Half of the core invariant — that a verifier never demands a cosignature the
log cannot produce — is enforced mechanically. Every `tlog_policy_pair()`
emits a `<name>.policy-pair-test` target which fails if there is any set of
witnesses that satisfies the log quorum but not the verifier quorum. Getting
the order of the steps above wrong therefore breaks the build rather than
production.

Note what this does *not* cover: offline data already in circulation. A
`tlog-proof` produced under an older policy is unaffected by the change here,
so step 3 must still wait for those to be re-logged. Relying parties should
check their own corpora against the candidate verifier policy, using the
`tlog_proof_test()` macro below or the `CheckProof` function it wraps.

## Building

This repository uses [Bazel](https://bazel.build/). Build all targets:

```bash
bazel build //...
```

The Bazel macros in `build_defs/tlog.bzl` provide:

- `concatenated_log_list(name, srcs)` — concatenates per-product log lists into
  a single combined log list, written to `<name>.txt`.
- `concatenated_witness_list(name, role, srcs)` — concatenates witness config
  files into a single witness list (`<name>.txt`) as seen by `role` (`"log"`
  or `"verifier"`), resolving role-qualified groups and failing the build if
  two files define the same name. The output contains only `witness` and
  `group` lines (no `log` or `quorum` lines). Also creates a
  `<name>.witness-list-test` target that validates the list.
- `witness_list_test(name, witness_list)` — checks that `witness_list` holds
  only `witness` and `group` lines, defines at least one witness, and is
  accepted by the tlog-policy parser once a `quorum none` line is appended.
- `tlog_log_policy(name, log_lists, witnesses, policy)` and
  `tlog_verifier_policy(name, log_lists, witnesses, policy)` — each generates a
  single tlog-policy file (`<name>.policy`) from log lists, witness configs,
  and a policy file defining product-level groups and the `quorum` rule, for a
  log operator and for verifiers respectively. They differ only in which
  definition they take of a group defined with `group-log` and `group-verifier`
  lines (in either a witness file or the policy file). Each also creates a
  `<name>.policy-test` target that validates the generated policy.
- `tlog_policy_pair(name, log_lists, witnesses, policy)` — generates a matched
  pair of log and verifier tlog-policy files from shared inputs, via a
  `tlog_log_policy()` target named `<name>-log` and a `tlog_verifier_policy()`
  target named `<name>-verifier`. Product-level quorum rollouts can diverge
  temporarily using `group-log` and `group-verifier` lines in the policy file.
  It also creates a `<name>.policy-pair-test` target asserting that any
  divergence is in the safe direction.
- `log_list_test(name, srcs)` — validates log-list files against the
  [tlog-list spec](https://c2sp.org/tlog-list).
- `tlog_policy_test(name, srcs)` — validates tlog-policy files against the
  [C2SP spec](https://c2sp.org/tlog-policy).
- `tlog_policy_pair_test(name, log_policy, verifier_policy)` — checks that
  `log_policy` is no stricter than `verifier_policy`. Instantiate it once per
  pair.
- `tlog_proof_test(name, policy, proofs, allow_empty_proofs=False)` — checks
  that `policy` accepts a corpus of already-issued tlog-proofs. Relying parties
  can point this at the proofs they have shipped, so that tightening a policy
  fails the build rather than breaking verification in the field. An empty
  proof file fails the test unless `allow_empty_proofs` is set.

