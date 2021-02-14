#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifndef HTTP_WITH_VLC
# error "Must be compile with HTTP_WITH_VLC"
#endif

#define MODULE_STRING "chall"
#define N_(x) (x)
#include <vlc_common.h>
#include <vlc_threads.h>
#include <vlc_plugin.h>
#include <vlc_access.h>
#include <vlc_interface.h>
#include <vlc_services_discovery.h>
#include <vlc_dialog.h>

#include "config.h"
#include "wb_loader.h"
#include "media-client.h"

#define PREFIX_SERVICE "chall"

static void error_VM(VMError r, services_discovery_t *p_sd) {
    if (r == VM_AUTH_FAIL) {
        msg_Err( p_sd, "Authentification fail" );
        vlc_dialog_display_error( p_sd, "Server authentification failed", "Wrong login/password" );
    } else {
        msg_Err( p_sd, "Unexpected error when loaded library: %d", r);
        vlc_dialog_display_error( p_sd, "Unknown error", "Unexpected error: %d", r);
    }
}

static int OpenSD( vlc_object_t* sd_this);
static void CloseSD( vlc_object_t* sd_this);
static void *RunSD(void* data);
static int OpenAccess( vlc_object_t* sd_this);
static void CloseAccess( vlc_object_t* sd_this);

struct services_discovery_sys_t {
    services_discovery_t* parent;
    vlc_array_t items;
    vlc_thread_t thread;
    struct Context ctx;
    struct MediaDir root_index;
};

struct access_sys_t {
    int fd;
};


VLC_SD_PROBE_HELPER(PREFIX_SERVICE, N_("Chall media services"), SD_CAT_INTERNET)

vlc_module_begin()
    set_shortname( "Chall" )
    set_description( N_("Chall media services") )
    set_category( CAT_PLAYLIST )
    set_subcategory( SUBCAT_PLAYLIST_SD )
    set_capability( "services_discovery", 0 )
    set_callbacks( OpenSD, CloseSD )
    add_string("media-server", DEFAULT_BASE_URL, "media server URL", "Change the media server to retrived the media", false)
    add_string("key-server-addr", DEFAULT_KEYSERVER_ADDRESS, "key server address", "Change the key server address", false)
    add_integer_with_range("key-server-port", DEFAULT_KEYSERVER_PORT, 1, 65535, "media server port", "Change the key server port", false)
    add_string("media-server-login", NULL, "Login", "Login", false)
    add_password("media-server-pass", NULL, "Password", "Password", false)

    add_submodule()
        set_category( CAT_INPUT )
        set_subcategory( SUBCAT_INPUT_ACCESS )
        set_callbacks( OpenAccess, CloseAccess )
        set_capability( "access", 0 )
        add_shortcut( PREFIX_SERVICE )
        add_string("chall-path", "", "", "", true)


    VLC_SD_PROBE_SUBMODULE

vlc_module_end()


static int OpenSD( vlc_object_t* sd_this) {

    services_discovery_t *p_sd = ( services_discovery_t* ) sd_this;
    services_discovery_sys_t *p_sys = malloc(sizeof(struct services_discovery_sys_t));

    if (p_sys == NULL) {
        return VLC_ENOMEM;
    }
    memset(p_sys, '\0', sizeof(struct services_discovery_sys_t));
    p_sys->root_index.is_open = false;
    p_sys->parent = p_sd;

    p_sd->p_sys = p_sys;
    p_sd->description = "chall media server";

    vlc_array_init(&p_sys->items);

    int key_server_port = var_CreateGetInteger(p_sd, "key-server-port");
    char* key_server_port_str;
    if (asprintf(&key_server_port_str, "%d", key_server_port) == -1) {
        vlc_array_clear(&p_sys->items);
        free(p_sys);
        return VLC_ENOMEM;
    }
    char* m_server = var_CreateGetString(p_sd, "media-server");
    char* key_server_addr = var_CreateGetString(p_sd, "key-server-addr");
    initContext(&p_sys->ctx, m_server, key_server_addr, key_server_port_str);
    free(key_server_addr);
    free(key_server_port_str);
    free(m_server);

    p_sys->ctx.vlc_sd = sd_this;

    char* login = var_CreateGetString(p_sd, "media-server-login");
    char* password = var_CreateGetString(p_sd, "media-server-pass");
    VMError r;
    if (login == NULL || password == NULL || *login == '\0' || *password == '\0') {
        msg_Info(p_sd, "Log as guest");
        r = remote_login(&p_sys->ctx, NULL, NULL);
    } else {
        msg_Info(p_sd, "Log as %s", login);
        r = remote_login(&p_sys->ctx, login, password);
    }
    free(login);
    free(password);

    if (r != VM_OK) {
        error_VM(r, p_sd);
        vlc_array_clear(&p_sys->items);
        freeContext(&p_sys->ctx);
        free(p_sys);
        return VLC_EGENERIC;
    }

    if ( vlc_clone( &p_sys->thread, RunSD, p_sys, VLC_THREAD_PRIORITY_LOW)) {
        vlc_array_clear(&p_sys->items);
        close_index(&p_sys->root_index);
        freeContext(&p_sys->ctx);
        free(p_sys);
        return VLC_EGENERIC;
    }

    return VLC_SUCCESS;
}

static void CloseSD( vlc_object_t* sd_this) {

    services_discovery_t *p_sd = ( services_discovery_t* ) sd_this;
    services_discovery_sys_t *p_sys = p_sd->p_sys;
    vlc_join( p_sys->thread, NULL );

    for (int i = 0; i < vlc_array_count(&p_sys->items); i++) {
        input_item_t* item = (input_item_t*) vlc_array_item_at_index(&p_sys->items, i);
        services_discovery_RemoveItem(p_sd, item);
        input_item_Release(item);
    }

    vlc_array_clear(&p_sys->items);
    close_index(&p_sys->root_index);
    freeContext(&p_sys->ctx);
    free(p_sys);
    p_sd->p_sys = NULL;
}

static inline void RegisteredFile(services_discovery_sys_t *p_sys, struct MediaFile* f) {
    uint64_t perm = get_current_permission(&p_sys->ctx);
    if (perm > f->perm) {
        return;
    }
    char* path = NULL;
    MediaResp r = get_file_path(f, &path);
    if (r != MEDIA_OK) {
        return;
    }

    input_item_t* item = input_item_NewFile(PREFIX_SERVICE "://", path, -1, ITEM_NET);
    if (item == NULL) {
        free(path);
        return;
    }
    free(path);

    vlc_array_append_or_abort(&p_sys->items, item);
    services_discovery_AddItem(p_sys->parent, item);
}

static inline void RegisteredDir(services_discovery_sys_t *p_sys, struct MediaDir* d) {
    if (!d->is_open) {
        MediaResp r = open_dir(&p_sys->ctx, d);
        if (r != MEDIA_OK) {
            return;
        }
    }

    for (size_t i = 0; i< d->nb_file; i++) {
        RegisteredFile(p_sys, &d->files[i]);
    }

    for (size_t i = 0; i< d->nb_subdir; i++) {
        RegisteredDir(p_sys, &d->subdir[i]);
    }
}

static void *RunSD(void* data) {

    services_discovery_sys_t *p_sys = (services_discovery_sys_t*) data;
    MediaResp r = open_index(&p_sys->ctx, &p_sys->root_index);

    if (r != MEDIA_OK) {
        msg_Err( p_sys->parent, "Unexpected error when load index: %d", r);
        vlc_dialog_display_error( p_sys->parent, "Unknown error when load index", "MediaResp %d", r);
        return NULL;
    }
    RegisteredDir(p_sys, &p_sys->root_index);

    return NULL;
}


static int OpenAccess( vlc_object_t* access_this) {

    stream_t *p_access = ( stream_t* ) access_this;
    access_sys_t *p_sys = malloc(sizeof(struct access_sys_t));

    if (p_sys == NULL) {
        return VLC_ENOMEM;
    }
    p_access->p_sys = p_sys;

    p_sys->fd = -1;

    msg_Info(p_access, "Success load library");


    return VLC_SUCCESS;
}

static void CloseAccess( vlc_object_t* access_this) {

    stream_t *p_access = ( stream_t* ) access_this;
    access_sys_t *p_sys = p_access->p_sys;

    if (p_sys->fd > 0) {
        close(p_sys->fd);
    }

    free(p_access->p_sys);
    p_access->p_sys = NULL;
}


