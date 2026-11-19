.PHONY: render check up down test lint
render: ; python3 tools/render.py
check:  ; python3 tools/check_policy.py
apptest: ; python3 tools/app_test.py
lint:   ; yamllint -d relaxed topology ansible
test:   ; sudo python3 tools/netns_test.py
up: render ; docker compose up -d --build
down:   ; docker compose down
