# Contributing

Thanks for your interest in improving Pixamine!

## Development setup

```bash
git clone <your-fork>
cd pixamine
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Running the tests

```bash
python tests/run_metrics.py /tmp/metrics.json validation   # detector validation
python tests/feature_tests.py                              # full feature pass (31 checks)
```

`feature_tests.py` regenerates the test fixtures automatically on first run
and needs a display; for headless environments set
`QT_QPA_PLATFORM=offscreen`. Both suites must pass before any PR is merged.

## Project layout

- `analysis` logic lives in the root modules (`carver.py`, `stego.py`,
  `tamper_analysis.py`, `metadata_engine.py`, `scoring.py`, `reporting.py`,
  `forensics.py`, `jpeg_structure.py`, `exif_utils.py`) and is orchestrated by
  `pipeline.py` — none of it imports a UI toolkit.
- `ui/` is the PySide6 front end. Views talk to `AppController` via signals;
  all heavy work runs on worker threads (`ui/workers.py`).
- `tests/fixtures.py` builds deterministic known-authentic and
  known-manipulated samples; its ground-truth table documents what each
  detector should find.

## Guidelines

- **Detectors must be validated.** Any change to an analysis function needs a
  before/after run of `run_metrics.py` over the fixture set, and detectors
  must carry an honest confidence value and limitation notes. We specifically
  guard against false positives on natural textures — see the periodic-texture
  fixture.
- **No analysis code in `ui/`**, no UI imports outside `ui/`.
- **Never block the UI thread**: anything slower than ~50 ms belongs on a
  worker.
- Keep the WCAG 2.1 AA contrast guarantees in `ui/theme.py` (the palette
  comments list the verified ratios; re-verify after any color change).
- Match the existing code style: typed function signatures, docstrings that
  explain the *why*, no dead code.

## Reporting issues

Include your OS, Python version, the image (or a description of it), and the
exact steps to reproduce. For detection-quality reports, a fixture built with
`tests/fixtures.py` plus the `run_metrics.py` output is enormously helpful.
