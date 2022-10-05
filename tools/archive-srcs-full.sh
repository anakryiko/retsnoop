#!/bin/sh

# Rely on a nifty git-archive-all.sh script from [0] to package up all the
# sources, including submodules.  This script just automates naming and
# creation of both .zip and .tar.gz archives.  It expects that this script is
# run from retsnoop repo root and git-archive-all.sh repo is checked out at
# the same level as retsnoop's repo.
#
#   [0] https://github.com/fabacab/git-archive-all.sh

../git-archive-all.sh/git-archive-all.sh --format zip srcs-full-$(src/retsnoop -V | cut -d' ' -f2).zip
../git-archive-all.sh/git-archive-all.sh --format tar.gz srcs-full-$(src/retsnoop -V | cut -d' ' -f2).tar.gz

git status

ls -la srcs-full-*




