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

MaybeLocal<Object> NodeWasm::WasmLookupImportCallback(Isolate* isolate,
                              MaybeLocal<Object> maybe_import_object,
                              Local<String> module_name,
                              Local<String> import_module) {
  v8::String::Utf8Value mod_name(isolate, module_name);
  v8::String::Utf8Value imp_name(isolate, import_module);
  if ((strcmp(*mod_name, "fopen") != 0) && (strcmp(*imp_name, "nodejs") != 0)) {
    return maybe_import_object;
  }

  Local<Context> context = isolate->GetCurrentContext();
  Environment* env = Environment::GetCurrent(context);
  Local<Object> import_object;
  if (maybe_import_object.IsEmpty()) {
    // Create importObject object
    Local<FunctionTemplate> im_ft = FunctionTemplate::New(isolate);
    im_ft->SetClassName(FIXED_ONE_BYTE_STRING(env->isolate(), "importObject"));
    Local<ObjectTemplate> im_obj_templ = ObjectTemplate::New(isolate, im_ft);
    Local<Object> im_obj = im_obj_templ->NewInstance(context).ToLocalChecked();

    // Create the fopen object
    Local<FunctionTemplate> fopen_ft = FunctionTemplate::New(isolate);
    fopen_ft->SetClassName(module_name);
    Local<ObjectTemplate> fopen_ot = ObjectTemplate::New(isolate, fopen_ft);
    Local<Object> fopen_obj = fopen_ot->NewInstance(context).ToLocalChecked();
    USE(im_obj->Set(context, module_name, fopen_obj));
    import_object = im_obj;
  } else {
     import_object = maybe_import_object.ToLocalChecked();
  }

  Local<Value> module_val = import_object->Get(context,
                                               module_name).ToLocalChecked();
  if (module_val->IsObject()) {
    Local<Object> module_obj = module_val->ToObject(context).ToLocalChecked();
    Local<Value> im_module_val = module_obj->Get(
        context, import_module).ToLocalChecked();
    if (im_module_val->IsUndefined()) {
      USE(module_obj->Set(context,
                          import_module,
                          env->NewFunctionTemplate(
                              WasmNodeJSFunction)->GetFunction()));
    }
  }
  return import_object;
}

void NodeWasm::WasmNodeJSFunction(const FunctionCallbackInfo<Value>& args) {
  std::cout << "WasmNodeJSFunction..." << '\n';
  args.GetReturnValue().Set(22);
}

}  // namespace wasm
