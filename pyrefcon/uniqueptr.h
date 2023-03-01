#ifndef PYREFCON__UNIQUE_PTR__H
#define PYREFCON__UNIQUE_PTR__H

#include <memory>

namespace {
void clang_analyzer_PyObject_Monitor_Assign(const void *, PyObject *);
}  // namespace

namespace std {

template <typename D>
class unique_ptr<PyObject, D> {
  PyObject *ptr = nullptr;

 public:
  unique_ptr() = default;
  unique_ptr(PyObject *p) : ptr(p) {
    clang_analyzer_PyObject_Monitor_Assign(this, p);
  }
  unique_ptr(unique_ptr &&that) : unique_ptr(that.release()) {}
  ~unique_ptr() { reset(); }
  unique_ptr &operator=(nullptr_t) {
    reset();
    return *this;
  }
  unique_ptr &operator=(unique_ptr &&that) {
    reset(that.release());
    return *this;
  }
  PyObject *release() {
    PyObject *ret = ptr;
    ptr = nullptr;
    clang_analyzer_PyObject_Monitor_Assign(this, nullptr);
    return ret;
  }
  void reset() {
    Py_CLEAR(ptr);
    clang_analyzer_PyObject_Monitor_Assign(this, nullptr);
  }
  void reset(PyObject *p) {
    Py_XDECREF(ptr);
    ptr = p;
    clang_analyzer_PyObject_Monitor_Assign(this, p);
  }
  PyObject *get() const { return ptr; }
  operator bool() const { return ptr; }
  PyObject *operator->() const { return ptr; }

  void swap(unique_ptr &that) = delete;  // Assume never used.
  D &get_deleter() const = delete;       // Assume never used.
  PyObject &operator*() const = delete;  // Assume never used.
};
}  // namespace std

#endif  // PYREFCON__UNIQUE_PTR__H
