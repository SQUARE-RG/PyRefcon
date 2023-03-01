# *PyRefcon* Tool

This directory contains the source code of the analyzer.

- File `PythonAPIChecker.cpp` is the checker implementation of *PyRefcon*.
- File `smtptr.cq` is the clang-query matcher of searching user defined refcount monitors.
- File `uniqueptr.h` implements `std::unique_ptr` based refcount monitors.
- Two diff files `pytorch_update.diff` and `scipy_update.diff` present the updates in *SciPy* and *PyTorch* for applying refcount monitor to these two projects.

The executable tool of *PyRefcon* and its usage documentations are stored in file `PyRefcon.tar.xz`.
