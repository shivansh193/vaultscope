# End-to-end specs (P4)

Cypress specs from the spec's commit map (Section 9). They drive a real stack
rather than a mock, so a green run means the browser, the API and the parser
all agree.

```bash
# terminal 1 — backend
source .venv/bin/activate && uvicorn api.main:app --port 8000

# terminal 2 — console
cd frontend && npm run dev

# terminal 3 — specs
cd frontend && npx cypress run          # or: npx cypress open
```

Against the Docker stack instead, where the console is served by nginx and the
backend lives behind `/api`:

```bash
docker compose up --build -d
cd frontend && CYPRESS_apiBase=/api npx cypress run
```

That run is the real check on `docker-compose.yml`: it exercises the static
export, the `/api` proxy and the WebSocket upgrade in one pass.

`fixtures/*.pcap` are generated, not hand-made — rebuild them with
`python scripts/generate_e2e_fixtures.py` if Block A changes the wire builders
in `tests/ike_parser/_build.py`.

These specs are deliberately outside `pytest`: they need a running stack, so
they are not part of the default `pytest` run.
