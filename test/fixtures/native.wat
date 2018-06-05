;; $ wat2wasm import.wat -o import.wasm
(module
 (func $fopen (import "__node" "fopen") (param i32) (param i32) (result i32))
  (func (export "fopen") (result i32)
    i32.const 1
    i32.const 2
    call $fopen
   )
)
