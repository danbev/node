#include "node.h"
#include "node_wasm.h"
#include "node_internals.h"
#include "env-inl.h"
#include <iostream>
#include "v8.h"

namespace node {

using v8::Context;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::Isolate;
using v8::Local;
using v8::MaybeLocal;
using v8::Object;
using v8::ObjectTemplate;
using v8::String;
using v8::Value;

Local<Object> newImportObject(Local<Context> context) {
  Isolate* isolate = context->GetIsolate();
  Local<FunctionTemplate> im_ft = FunctionTemplate::New(isolate);
  im_ft->SetClassName(FIXED_ONE_BYTE_STRING(isolate, "importObject"));
  Local<ObjectTemplate> im_obj_templ = ObjectTemplate::New(isolate, im_ft);
  return im_obj_templ->NewInstance(context).ToLocalChecked();
}

Local<Object> newFopenObject(Local<Context> context,
                             Local<String> module_name) {
  Isolate* isolate = context->GetIsolate();
  Local<FunctionTemplate> fopen_ft = FunctionTemplate::New(isolate);
  fopen_ft->SetClassName(module_name);
  Local<ObjectTemplate> fopen_ot = ObjectTemplate::New(isolate, fopen_ft);
  return fopen_ot->NewInstance(context).ToLocalChecked();
}

bool isNodeWasmImport(Local<String> module_name,
                      Local<String> import_module,
                      Local<Context> context) {
  v8::String::Utf8Value mod_name(context->GetIsolate(), module_name);
  v8::String::Utf8Value imp_name(context->GetIsolate(), import_module);
  if (strcmp(*mod_name, "__node") != 0) {
    return false;
  }
  return strcmp(*imp_name, "fopen") == 0;
}

MaybeLocal<Object> NodeWasm::WasmLookupImportCallback(Isolate* isolate,
                              MaybeLocal<Object> maybe_import_object,
                              Local<String> module_name,
                              Local<String> import_module) {
  Local<Context> context = isolate->GetCurrentContext();
  Environment* env = Environment::GetCurrent(context);
  if (!isNodeWasmImport(module_name, import_module, context)) {
    return maybe_import_object;
  }

  Local<Object> import_object;
  if (maybe_import_object.IsEmpty()) {
    import_object = newImportObject(context);
    Local<Object> fopen_obj = newFopenObject(context, module_name);
    USE(import_object->Set(context, module_name, fopen_obj));
  } else {
     import_object = maybe_import_object.ToLocalChecked();
  }

  Local<Value> module_val = import_object->Get(context,
                                               module_name).ToLocalChecked();
  if (module_val->IsObject()) {
    Local<Object> module_obj = module_val->ToObject(context).ToLocalChecked();
    Local<Value> im_module_val = module_obj->Get(context,
        import_module).ToLocalChecked();
    if (im_module_val->IsUndefined()) {
      auto ft = env->NewFunctionTemplate(Fopen)->GetFunction();
      USE(module_obj->Set(context, import_module, ft));
    }
  }
  return import_object;
}

void NodeWasm::Fopen(const FunctionCallbackInfo<Value>& args) {
  std::cout << "NodeWasm::fopen..." << '\n';
  args.GetReturnValue().Set(22);
}


}  // namespace node
