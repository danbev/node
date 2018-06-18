#include "async_wrap.h"
#include "node_internals.h"
#include "libplatform/libplatform.h"
#include "v8-profiler.h"

#include <string>
#include "gtest/gtest.h"
#include "node_test_fixture.h"
#include "util-inl.h"

using v8::Local;
using v8::String;
using v8::HandleScope;
using v8::HeapProfiler;
using v8::HeapSnapshot;
using v8::HeapGraphNode;
using v8::Persistent;
using v8::Isolate;

class GraphBuilderTest : public EnvironmentTestFixture {
 private:
  virtual void TearDown() {
    NodeTestFixture::TearDown();
  }
};

const v8::HeapGraphNode* GetNode(const HeapGraphNode* parent,
                                 HeapGraphNode::Type type,
                                 const char* name,
                                 Isolate* isolate) {
  for (int i = 0, count = parent->GetChildrenCount(); i < count; ++i) {
    const v8::HeapGraphNode* node = parent->GetChild(i)->GetToNode();
    String::Utf8Value node_name(isolate, node->GetName());
    if (node->GetType() == type && strcmp(name, *node_name) == 0) {
      return node;
    }
  }
  return nullptr;
}

TEST_F(GraphBuilderTest, BuildGraph) {
  const v8::HandleScope handle_scope(isolate_);
  const Argv argv {"node",
                   "--heap-profiler-use-embedder-graph",
                   "process.version"};
  Env env {handle_scope, argv};

  Local<String> one_name = FIXED_ONE_BYTE_STRING(isolate_, "one");
  Persistent<String> one(isolate_, one_name);
  one.SetWrapperClassId(NODE_ASYNC_ID_OFFSET);

  Local<String> two_name = FIXED_ONE_BYTE_STRING(isolate_, "two");
  Persistent<String> two(isolate_, two_name);
  two.SetWrapperClassId(NODE_ASYNC_ID_OFFSET);

  HeapProfiler* heap_profiler = isolate_->GetHeapProfiler();
  const HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();

  const HeapGraphNode* group = GetNode(snapshot->GetRoot(),
                                         HeapGraphNode::kNative,
                                         "nodejs-group",
                                         isolate_);
  EXPECT_EQ(HeapGraphNode::kNative, group->GetType());
  EXPECT_STREQ("nodejs-group", *String::Utf8Value(isolate_,
                                                  group->GetName()));
  EXPECT_EQ(2, group->GetChildrenCount());

  const v8::HeapGraphEdge* child_1 = group->GetChild(0);
  EXPECT_EQ(group, child_1->GetFromNode());
  EXPECT_STREQ("one", *String::Utf8Value(isolate_,
                                         child_1->GetToNode()->GetName()));

  const v8::HeapGraphEdge* child_2 = group->GetChild(1);
  EXPECT_EQ(group, child_2->GetFromNode());
  EXPECT_STREQ("two", *String::Utf8Value(isolate_,
                                         child_2->GetToNode()->GetName()));
}

class FakeAsyncWrap : public node::AsyncWrap {
 public:
  FakeAsyncWrap(node::Environment* env, v8::Local<v8::Object> object)
    : AsyncWrap(env, object, AsyncWrap::ProviderType::PROVIDER_TCPWRAP) {
  }
 private:
  size_t self_size() const { return 0; }
};

TEST_F(GraphBuilderTest, BuildGraphWithAsyncObject) {
  const v8::HandleScope handle_scope(isolate_);
  const Argv argv {"node",
                   "--heap-profiler-use-embedder-graph",
                   "process.version"};
  Env env {handle_scope, argv};

  Local<v8::FunctionTemplate> ft = v8::FunctionTemplate::New(isolate_);
  ft->SetClassName(FIXED_ONE_BYTE_STRING(isolate_, "Object"));
  ft->InstanceTemplate()->SetInternalFieldCount(1);
  Local<v8::ObjectTemplate> ot = v8::ObjectTemplate::New(isolate_, ft);
  Local<v8::Object> object = ot->NewInstance(
      isolate_->GetCurrentContext()).ToLocalChecked();

  //  AsyncWrap's constructor will set the wrapper class id.
  auto async_wrap = std::unique_ptr<FakeAsyncWrap>(
     new FakeAsyncWrap(*env, object));

  HeapProfiler* heap_profiler = isolate_->GetHeapProfiler();
  const HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();

  const HeapGraphNode* group = GetNode(snapshot->GetRoot(),
                                         HeapGraphNode::kNative,
                                         "nodejs-group",
                                         isolate_);
  ASSERT_EQ(1, group->GetChildrenCount());
  const v8::HeapGraphEdge* mock_edge = group->GetChild(0);
  EXPECT_EQ(group, mock_edge->GetFromNode());

  CHECK(ValidateSnapshot(snapshot));
}
