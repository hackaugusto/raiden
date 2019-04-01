CODE_DIRS = src/ tests/
ISORT_PARAMS = --ignore-whitespace --settings-path . --recursive $(CODE_DIRS)

all: lint

lint: mypy
	flake8 $(CODE_DIRS)
	isort $(ISORT_PARAMS) --diff --check-only

mypy:
	mypy $(CODE_DIRS)

isort:
	isort $(ISORT_PARAMS)

test:
	py.test -v tests
