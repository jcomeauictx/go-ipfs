PYTHON_SOURCES := $(wildcard *.py)
PYLINT_SOURCES := $(PYTHON_SOURCES:.py=.pylint)
DOCTEST_SOURCES := $(PYTHON_SOURCES:.py=.doctest)
VERBOSE ?= -v
export
all: pylint doctests
pylint: $(PYLINT_SOURCES)
doctests: $(DOCTEST_SOURCES)
%.pylint: %.py
	pylint3 $<
%.doctest: %.py
	python3 -m doctest $(VERBOSE) $<
env:
	$@
