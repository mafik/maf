# namespace maf

`::maf` is a personal effort to organize my various C++ libraries (starting ~2022 Q3). It's meant to simplify maintenance & code reuse.

## Organization

Inside `~/C++/src/` there is a bunch of reusable C++ sources with `*.hh` and `*.cc` extensions. Various projects should hardlink them into their own `src/` directories.

Different projects can live in arbitrary directories. For example `~/Pulpit/gatekeeper/` or `~/Pulpit/automat/`. Projects may also be hosted on external repositories, such as GitHub.

Files in `~/C++/src/` and in projects' `src/` directories should never collide. If their names are identical then they should be hardlinked.

## Building

Code may be built using the `run` script (the script & `run_py/` should be hardlinked in each project).

`run_py` scans the project files to build a dependency graph. The user can then specify which targets to build. The script follows a convention that allows projects to avoid having to define their own Makefiles.

1. Sources are first scanned for `.py` files. Each `.py` file can modify build configuration and add new steps.
2. Then files are scanned for `.cc` and `.hh` files. Intermediate object files & executables are derived based on them.
3. Finally, a special `tests` target is generated that runs all tests.
