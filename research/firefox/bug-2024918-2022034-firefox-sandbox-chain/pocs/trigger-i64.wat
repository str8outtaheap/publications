(module
  ;; Pseudocode: type Inner = { field0: i64 }
  (type $Inner (struct (field (mut i64))))
  ;; Pseudocode: type Outer = { inner: Inner? }
  (type $Outer (struct (field (mut (ref null $Inner)))))
  ;; Pseudocode: type Container = { inner: Inner? }
  (type $Container (struct (field (mut (ref null $Inner)))))

  ;; Pseudocode: let saved = null
  ;; saved keeps the Container reachable after run() returns.
  (global $g (mut (ref null $Container)) (ref.null $Container))

  (func (export "run") (param $n i32)
    (local $outer (ref $Outer))
    (local $inner (ref $Inner))
    (local $container (ref $Container))
    (local $i i32)

    ;; Pseudocode: outer = new Outer(null)
    (local.set $outer (struct.new $Outer (ref.null $Inner)))
    ;; Pseudocode: inner = new Inner(0xff)
    ;; The vulnerable optimization removes this field initialization.
    (local.set $inner (struct.new $Inner (i64.const 0xff)))
    ;; Pseudocode: outer.inner = inner
    (struct.set $Outer 0 (local.get $outer) (local.get $inner))
    ;; Pseudocode: container = new Container(null)
    ;; Pseudocode: saved = container
    (local.set $container (struct.new $Container (ref.null $Inner)))
    (global.set $g (local.get $container))

    ;; Pseudocode: do {
    (loop $loop
      ;; Pseudocode: container.inner = outer.inner
      (struct.set $Container 0
        (local.get $container)
        (struct.get $Outer 0 (local.get $outer)))
      ;; Pseudocode: outer.inner = inner
      (struct.set $Outer 0 (local.get $outer) (local.get $inner))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      ;; Pseudocode: } while (++i < n)
      (br_if $loop (i32.lt_s (local.get $i) (local.get $n)))))

  ;; Pseudocode: return saved.inner.field0
  ;; With the initializer removed, this returns leftover bytes as an i64.
  (func (export "read") (result i64)
    (struct.get $Inner 0
      (struct.get $Container 0 (global.get $g)))))
