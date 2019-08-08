/*
 * Copyright 2018-present MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <bson/bson.h>

#include "mongocrypt-status-private.h"

mongocrypt_status_t *
mongocrypt_status_new (void)
{
   return bson_malloc0 (sizeof (mongocrypt_status_t));
}


void
mongocrypt_status_set (mongocrypt_status_t *status,
                       mongocrypt_status_type_t type,
                       uint32_t code,
                       const char *message,
                       int32_t message_len)
{
   if (message_len < 0) {
      message_len = (int32_t) strlen (message) + 1;
   }
   if (MONGOCRYPT_STATUS_MSG_LEN < message_len - 1) {
      message_len = MONGOCRYPT_STATUS_MSG_LEN;
   }
   bson_strncpy (status->message, message, message_len);
   status->type = type;
   status->code = code;
}

const char *
mongocrypt_status_message (mongocrypt_status_t *status, uint32_t *len)
{
   BSON_ASSERT (status);

   if (mongocrypt_status_ok (status)) {
      return NULL;
   }
   if (len) {
      *len = status->len;
   }
   return status->message;
}


uint32_t
mongocrypt_status_code (mongocrypt_status_t *status)
{
   BSON_ASSERT (status);

   return status->code;
}


mongocrypt_status_type_t
mongocrypt_status_type (mongocrypt_status_t *status)
{
   BSON_ASSERT (status);

   return status->type;
}


bool
mongocrypt_status_ok (mongocrypt_status_t *status)
{
   BSON_ASSERT (status);

   return (status->type == MONGOCRYPT_STATUS_OK);
}

void
_mongocrypt_status_copy_to (mongocrypt_status_t *src, mongocrypt_status_t *dst)
{
   BSON_ASSERT (dst);
   BSON_ASSERT (src);

   if (dst == src) {
      return;
   }

   dst->type = src->type;
   dst->code = src->code;
   dst->len = src->len;
   bson_strncpy (
      dst->message, src->message, (size_t) MONGOCRYPT_STATUS_MSG_LEN - 1);
}

void
_mongocrypt_status_reset (mongocrypt_status_t *status)
{
   BSON_ASSERT (status);

   status->type = MONGOCRYPT_STATUS_OK;
   status->code = 0;
   status->len = 0;
   memset (status->message, 0, MONGOCRYPT_STATUS_MSG_LEN);
}

void
mongocrypt_status_destroy (mongocrypt_status_t *status)
{
   if (!status) {
      return;
   }

   bson_free (status);
}
