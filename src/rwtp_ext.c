#include <rope.h>

zframe_t *rwtp_frame_to_zframe(const rwtp_frame *self) {
    zframe_t *result = zframe_new(NULL, self->iovec_len);
    if (!result) {
        return NULL;
    }
    memcpy(zframe_data(result), self->iovec_data, self->iovec_len);
    return result;
}

rwtp_frame *rwtp_frame_from_zframe(const zframe_t *f) {
    rwtp_frame *result = rwtp_frame_new(zframe_size((zframe_t *)f), NULL);
    if (!result) {
        return NULL;
    }
    memcpy(result->iovec_data, zframe_data((zframe_t *)f), result->iovec_len);
    return result;
}

zmsg_t *rwtp_frame_to_zmsg(const rwtp_frame *self) {
    zmsg_t *result = zmsg_new();
    for (const rwtp_frame *curr = self; curr; curr = curr->frame_next) {
        zmsg_addmem(result, curr->iovec_data, curr->iovec_len);
    }
    return result;
}

rwtp_frame *rwtp_frame_from_zmsg(zmsg_t *zmsg) {
    rwtp_frame *head = NULL, *prev = NULL, *curr = NULL;
    for (zframe_t *f = zmsg_first(zmsg); f; f = zmsg_next(zmsg)) {
        curr = rwtp_frame_new(zframe_size(f), NULL);
        if (!curr) {
            if (head) {
                rwtp_frame_destroy_all(head);
            }
        }
        memcpy(curr->iovec_data, zframe_data(f), curr->iovec_len);
        if (!head) {
            head = curr;
        }
        if (prev) {
            prev->frame_next = curr;
        }
        prev = curr;
    }
    return head;
}

rwtp_frame *rwtp_frame_from_zuuid(zuuid_t **uuid){
    rwtp_frame *result = rwtp_frame_new(zuuid_size(*uuid), NULL);
    memcpy(result->iovec_data, zuuid_data(*uuid), zuuid_size(*uuid));
    zuuid_destroy(uuid);
    return result;
}

zuuid_t *rwtp_frame_to_zuuid(rwtp_frame *self){
    assert(self->iovec_len==ZUUID_LEN);
    return zuuid_new_from(self->iovec_data);
}
