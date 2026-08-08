(module
  ;; The PoC replaces the native target behind this imported function.
  (import "env" "target"
    (func $target
      (param i64 i64 i64 i64 i64 i64 i64 i64)
      (result i64)))

  (func (export "call")
    (param i64 i64 i64 i64 i64 i64 i64 i64)
    (result i64)
    ;; Pseudocode: return target(x0, x1, x2, x3, x4, x5, x6, x7)
    ;; On arm64, these eight i64 arguments reach target in x0 through x7.
    local.get 0
    local.get 1
    local.get 2
    local.get 3
    local.get 4
    local.get 5
    local.get 6
    local.get 7
    call $target))
