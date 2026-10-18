PY ?= python3

.PHONY: demo test cov serve smoke
demo:            ## regenerate synthetic logs, reports and dashboard data
	$(PY) -m loganalyzer demo
test:
	$(PY) -m pytest
cov:
	$(PY) -m pytest --cov=loganalyzer --cov-report=term-missing
serve:           ## dashboard at http://localhost:8000
	$(PY) -m http.server 8000 --directory dashboard
smoke:           ## needs: npm i playwright-core, and Chrome/Chromium
	node scripts/dashboard_smoke.js http://127.0.0.1:8000 screenshots
