# OSS-Fuzz integration for edk2fuzz
#
# These files are mirrored from this repo into the upstream OSS-Fuzz
# repository at projects/edk2fuzz/.  Layout:
#
#   oss-fuzz/projects/edk2fuzz/project.yaml   -> projects/edk2fuzz/project.yaml
#   oss-fuzz/projects/edk2fuzz/Dockerfile     -> projects/edk2fuzz/Dockerfile
#   oss-fuzz/projects/edk2fuzz/build.sh       -> projects/edk2fuzz/build.sh
#
# Local validation:
#   git clone --depth 1 https://github.com/google/oss-fuzz /tmp/oss-fuzz
#   cp -r oss-fuzz/projects/edk2fuzz /tmp/oss-fuzz/projects/
#   cd /tmp/oss-fuzz
#   python3 infra/helper.py build_image   --no-pull edk2fuzz
#   python3 infra/helper.py build_fuzzers --sanitizer address --engine afl edk2fuzz
#   python3 infra/helper.py check_build   --sanitizer address --engine afl edk2fuzz
#
# Per https://google.github.io/oss-fuzz/getting-started/new-project-guide/
