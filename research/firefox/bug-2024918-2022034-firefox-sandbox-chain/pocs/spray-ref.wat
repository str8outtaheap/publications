(module
  ;; Pseudocode: type Spray = { field0: anyref }
  (type $Spray (struct (field (mut anyref))))

  ;; Pseudocode: const table = [null]
  (table $table 1 anyref)

  (func (export "spray") (param $count i32) (param $value externref)
    (local $i i32)
    (local $cell (ref null $Spray))
    ;; Pseudocode: do {
    (loop $loop
      ;; Pseudocode: cell = new Spray(value)
      (local.set $cell
        (struct.new $Spray (any.convert_extern (local.get $value))))

      ;; Pseudocode: table[0] = cell
      ;; 1. struct.new can be scalar-replaced when the object does not escape.
      ;; 2. table[0] makes cell escape, so SpiderMonkey cannot remove the
      ;;    allocation.
      ;; 3. The one-slot table replaces the previous reference, making the old
      ;;    $Spray unreachable and eligible for collection.
      (table.set $table (i32.const 0) (local.get $cell))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      ;; Pseudocode: } while (++i < count)
      (br_if $loop (i32.lt_s (local.get $i) (local.get $count))))

    ;; Pseudocode: table[0] = null
    ;; Once spray() returns, no $Spray remains reachable.
    (table.set $table (i32.const 0) (ref.null any))))
