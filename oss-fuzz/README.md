# OSS-Fuzz integration for edk2-metis
#
# These files are mirrored from this repo into the upstream OSS-Fuzz
# repository at projects/edk2-metis/.  Layout:
#
#   oss-fuzz/projects/edk2-metis/project.yaml   -> projects/edk2-metis/project.yaml
#   oss-fuzz/projects/edk2-metis/Dockerfile     -> projects/edk2-metis/Dockerfile
#   oss-fuzz/projects/edk2-metis/build.sh       -> projects/edk2-metis/build.sh
#
# Local validation:
#   git clone --depth 1 https://github.com/google/oss-fuzz /tmp/oss-fuzz
#   cp -r oss-fuzz/projects/edk2-metis /tmp/oss-fuzz/projects/
#   cd /tmp/oss-fuzz
#   python3 infra/helper.py build_image   --no-pull edk2-metis
#   python3 infra/helper.py build_fuzzers --sanitizer address --engine afl edk2-metis
#   python3 infra/helper.py check_build   --sanitizer address --engine afl edk2-metis
#
# Per https://google.github.io/oss-fuzz/getting-started/new-project-guide/
