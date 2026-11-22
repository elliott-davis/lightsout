# Differential corpus for the flagd load pipeline

Each input file here is paired with `<input>.expected.json`: the flags that **flagd core v0.19.3 actually loaded** from
that file. `TestEmulation_MatchesFlagd_FLG2` runs the port of the load pipeline in `pipeline.go` over every input and
asserts it yields the recorded flags, so the port stays honest without importing flagd. The expected files are
recorded, never written by hand.

- **flagd version:** `github.com/open-feature/flagd/core v0.19.3`.
- **Recorded:** 2026-11-22.
- **Inputs:** the cases of the round-2 and round-3 security reviews (`r2-*`, `r3-*`: array forms, case variants, `$ref`
  and `$evaluators` splices, YAML key cases, multi-document files, odd extensions, the lift and key-order splices, alias
  bombs) and the false-positive files of the round-3 Go review (`go-r3-*`: Codecov, Helm, i18n, lock files and so on).
  A file name keeps its real extension, including the odd ones (`.jsoné`, `.json٣`), because the extension picks the
  decoder.

## What was run

`fprobe` (the reviewers' probe) loads a file the way flagd does, with `utils.ConvertToJSON` and
`evaluator.JSON.SetState`, and then resolves the keys it is given. It cannot list the flags, so the expected files were
recorded with `fdump`, the same program with the last step replaced: it lists the store with `store.GetAll`. Both are
built from the same module.

```go
js, err := utils.ConvertToJSON(data, filepath.Ext(path), "")   // stage "convert" on error
st, _ := store.NewStore(lg, []string{"src"})
ev := evaluator.NewJSON(lg, st)
err = ev.SetState(sync.DataSync{FlagData: js, Source: "src"})  // stage "load" on error
flags, _, _ := st.GetAll(ctx, &store.Selector{})               // stage "ok"
```

`fdump` lives in [`tools/fdump`](../../../../tools/fdump), a separate module so flagd never enters the factory's
module graph or its bill of materials (NFR-8). Where it should live long term is an open question
([#10](https://github.com/elliott-davis/lightsout/issues/10)). To re-record or check the corpus:

```sh
(cd tools/fdump && go build -o "$OLDPWD/bin/fdump" .)
for f in internal/switches/testdata/flagd-differential/*; do case $f in *.expected.json|*README.md) continue;; esac
  bin/fdump "$f" | cmp -s - "$f.expected.json" || echo "changed: $f"; done
```

An expected file holds `stage` (`convert`, `load` or `ok`) and, for `ok`, the flags sorted by key with `key`, `state`,
`defaultVariant`, `variants` and `hasTargeting` (whether the flag has a `targeting` value of any kind).

Run the corpus again against each new flagd version (WI-23a): a change in a recorded result means the port, and the
canonical form built on it, must be reviewed.
