/*
 *  Copyright 2021 Nicolas Surbayrole
 *  Copyright 2021 Quarkslab
 *  Copyright 2021 Association STIC
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "wb_loader.h"


int main(int argc, char** argv) {

    if (curl_global_init(CURL_GLOBAL_ALL) != 0) abort();
    struct Context ctx;
    initContext(&ctx, NULL, NULL, NULL);

    while (1) {
        struct vmsign t;
        memset(&t, 0, sizeof(struct vmsign));
        VMError e = hsign(&ctx, 0, &t);
        uint64_t perm = get_current_permission(&ctx);

        printf("hsign return %d, m=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x, ident=%02x%02x%02x%02x, perm=%016lx\n",
            e,
            t.data[0], t.data[1], t.data[2], t.data[3],
            t.data[4], t.data[5], t.data[6], t.data[7],
            t.data[8], t.data[9], t.data[10], t.data[11],
            t.data[12], t.data[13], t.data[14], t.data[15],
            t.ident[0], t.ident[1], t.ident[2], t.ident[3],
            perm);


        sleep(30);
    }


    return 0;
}
