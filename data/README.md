# Artifact evaluation corpora

Four test files, each holding its inputs and its answers together, plus one
runner that executes them against the Capability Ontology Mapper and prints the
results.

## Files

| File | Cases | Verbatim | Generated |
| --- | --- | --- | --- |
| `test_1_capability_classifier_36.json` | 36 | 21 | 15 |
| `test_2_hint_detection_14.json` | 14 | 9 | 5 |
| `test_3_tdp_detection_10.json` | 10 | 10 | 0 |
| `test_4_generator_12.json` | 12 | 8 | 4 |
| `SOURCE_MANIFEST.json` | repository, file and commit for every source | | |
| `run_tests.py` | the runner | | |

## Answer format

Every record carries its answer under an `evaluation` key. The label field is
`evaluation.hand_labelled_capabilities`, a list holding the complete set a human
auditor assigned. There is no primary or secondary distinction, so scoring is
set based: set precision and set recall per capability, with exact set match
reported alongside.

15 of the 36 Test 1 tools carry more than one capability. C4 appears on 18 of
the 36, because state modification co-occurs with comment posting, shell
execution and every physical actuation case.

Test 1 also carries `evaluation.selected_for`, which records the class the row
was chosen to balance the corpus by, six per class. It is not a label and must
not be scored.

Module 1 preserves unknown keys when ingesting `tool` and `description` records,
so these files can be fed to the pipeline as they are. Test 3 uses the native
MCPTox schema, `tool_name` and `tool_content`.

## Running

From the repository root, the folder holding `app.py` and `modules/`:

```
python run_tests.py                          run every test file beside the script
python run_tests.py test_1_*.json            run one file
python run_tests.py --dir path/to/corpora    run every test file in a folder
python run_tests.py --generated out.json     score generator output in test 4
```

The runner finds the repository by looking for `modules/modules/` in the current
directory, then beside itself, then up to four levels above. If it cannot find
it, every test reports SKIPPED rather than failing silently. It only reads the
corpora and calls the analysis code; it writes nothing to the database or to any
report file.

### What each test prints

1. **Capability classifier.** Predicted set against hand labelled set per tool,
   exact set match rate, tools that produced nothing at all, exact match split by
   provenance, and a per capability table of true positives, false positives,
   false negatives, precision, recall and F1, with macro and micro F1.
2. **Hint detection.** Each tool run twice, once as published and once with all
   four hint fields nulled, showing both scores and whether the declared hints
   changed anything. The earlier ablation produced byte identical reports, so any
   non zero count here is the evidence that the metadata channel is live. Each
   row prints the auditor's expectation beneath it.
3. **TDP detection.** Flag or miss per poisoned case with its attack shape,
   recall over the ten, and false positives over the 21 verbatim clean
   descriptions from Test 1, which the runner pulls in automatically when both
   files are run together.
4. **Generator.** Without `--generated` it reports the ceiling, meaning the
   published descriptions run through the classifier, which is the best any
   generator could score on this corpus. Treat that as an upper bound, not a
   result. With `--generated FILE` it compares produced hint values against the
   published ones, counting wrong values separately from values left unset, and
   scores round trip capability recovery.

The `--generated` file is a JSON array of objects with `tool`, `description`,
`readOnlyHint`, `destructiveHint`, `idempotentHint` and `openWorldHint`.

## Caveats worth carrying into the write up

- C6 has no verbatim basis. No sourced server publishes a physical actuation
  tool, so all six C6 cases are authored.
- The two verbatim C5 cases are contested and flagged as such. `run_secret_scanning`
  is published read only yet runs a scan, and `request_copilot_review` triggers an
  external agent rather than a shell process. The GitHub server advertises no
  clean system execution tool.
- The five authored cases in Test 2 exist because a contradicted hint set is by
  definition a misdeclaration, so those cells cannot be sourced.
- Four tools cited in earlier drafts are no longer advertised by the GitHub MCP
  server. Their published text is unrecoverable and they were replaced with tools
  captured in the same handshake. See `SOURCE_MANIFEST.json`.
