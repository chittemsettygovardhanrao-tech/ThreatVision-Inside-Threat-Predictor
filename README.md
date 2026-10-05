# ThreatVision — Insider Threat Predictor

A defensive, consent-based Python/PyQt6 UEBA prototype with synthetic data,
SQLite persistence, simulation-first response actions, anomaly/risk foundations,
and privacy-preserving sentiment analysis.

## Important

Use only on systems and data for which you have explicit authorization.
Monitoring is designed to be consent-based. Response actions default to
SIMULATION and must not be treated as authorization to lock accounts,
quarantine files, or otherwise disrupt systems.

## Architecture

Collectors -> Event Bus -> Feature Engineering -> ML/NLP -> Risk Assessment
-> Policy Engine -> Simulation-first Response -> SQLite/Audit -> PyQt6 GUI

## Windows setup

```powershell
cd path\to\threatvision
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks activation, use:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\.venv\Scripts\Activate.ps1
```

## Run

```powershell
python -m threatvision.main
```

Click **Generate 1,000 Training Events**, then **Start Synthetic Monitoring**.

The application creates `data/threatvision.db` and `logs/threatvision.log`.

## Tests

```powershell
pytest -q
```

## Project

The package is deliberately structured so the GUI, collectors, ML pipeline,
NLP, policy engine, and persistence can be expanded independently.
