#include <uv.h>
#include <zmq.h>

typedef void* roke_ctx;

roke_ctx roke_ctx_init();

void roke_ctx_deinit(roke_ctx ctx);
