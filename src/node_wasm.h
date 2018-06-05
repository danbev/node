#ifndef SRC_NODE_WASM_H_
#define SRC_NODE_WASM_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "env.h"
#include "v8.h"

namespace node {

class NodeWasm {
 public:
  static v8::MaybeLocal<v8::Object> WasmLookupImportCallback(
      v8::Isolate* isolate,
      v8::MaybeLocal<v8::Object> maybe_import_object,
      v8::Local<v8::String> module_name,
      v8::Local<v8::String> import_module);

 private:
  static void WasmNodeJSFunction(
      const v8::FunctionCallbackInfo<v8::Value>& args);
};

}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#endif  // SRC_NODE_WASM_H_
