#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifndef HTTP_WITH_VLC
# error "Must be compile with HTTP_WITH_VLC"
#endif

#define MODULE_STRING "chall"
#include <vlc_common.h>
#include <vlc_atomic.h>
#include <vlc_threads.h>
#include <vlc_plugin.h>
#include <vlc_access.h>
#include <vlc_interface.h>
#include <vlc_services_discovery.h>
#include <vlc_dialog.h>
#include <vlc_url.h>

#include "config.h"
#include "wb_loader.h"
#include "media-client.h"

#define PREFIX_SERVICE "chall"

#define DOMAIN  PREFIX_SERVICE "-plugin"
#define _(str)  dgettext(DOMAIN, str)
#define N_(str) (str)

static atomic_flag need_init = ATOMIC_FLAG_INIT;
static bool is_init = false;

struct {
    struct Context ctx;
    struct MediaDir root_index;

    vlc_mutex_t ctx_mutex;
} global_ctx;

static void global_init() {
    if (is_init) {
        return;
    }
    if (atomic_flag_test_and_set(&need_init)) {
        do {
            usleep(100);
            __sync_synchronize();
        } while (! is_init);
        return;
    }
    vlc_mutex_init(&global_ctx.ctx_mutex);
    initContext(&global_ctx.ctx, NULL, NULL, NULL);
    memset(&global_ctx.root_index, '\0', sizeof(struct MediaDir));
    global_ctx.root_index.is_open = false;

    is_init = true;
}

static void get_context(stream_t* vlc_obj) {
    vlc_mutex_lock(&global_ctx.ctx_mutex);
    global_ctx.ctx.vlc_obj = vlc_obj;
}

static void release_context() {
    vlc_mutex_unlock(&global_ctx.ctx_mutex);
}

static void error_VM(VMError r, stream_t *p_access) {
    if (r == VM_AUTH_FAIL) {
        msg_Err( p_access, "Authentification fail" );
        vlc_dialog_display_error( p_access, "Server authentification failed", "Wrong login/password" );
    } else {
        msg_Err( p_access, "Unexpected error when loaded library: %d", r);
        vlc_dialog_display_error( p_access, "Unknown error", "Unexpected error: %d", r);
    }
}
static void error_Media(MediaResp r, stream_t *p_access, const char* path) {
    switch (r) {
        case MEDIA_EMPTY:
            msg_Err( p_access, "Empty file: %s", path);
            vlc_dialog_display_error( p_access, "Empty file", "Empty file: %s", path);
            break;
        case MEDIA_PATH_INVALID:
            msg_Err( p_access, "Path invalid: %s", path);
            vlc_dialog_display_error( p_access, "Path invalid", "Path invalid: %s", path);
            break;
        case MEDIA_WRONG_PERMS:
            msg_Err( p_access, "Permission denied: %s", path);
            vlc_dialog_display_error( p_access, "Permission denied", "Permission denied: %s", path);
            break;
        default:
            msg_Err( p_access, "Unexpected error when loaded '%s': %d", path, r);
            vlc_dialog_display_error( p_access, "Unknown error", "Unexpected error when loaded '%s': %d", path, r);
            break;
    }
}

static int OpenSD( vlc_object_t* sd_this);
static void CloseSD( vlc_object_t* sd_this);
static int OpenAccess( vlc_object_t* sd_this);
static void CloseAccess( vlc_object_t* sd_this);
static void *DownloadAccess(void* data);

static int AccessSeek(stream_t *p_access, uint64_t pos);
static int AccessControl(stream_t *p_access, int query, va_list args);
static ssize_t AccessRead(stream_t *p_access, void *buf, size_t size);
static int AccessReadDir(stream_t *p_access, input_item_node_t* item);

struct services_discovery_sys_t {
    input_item_t* root_item;
    services_discovery_t* parent;
    vlc_thread_t thread;
};

struct access_sys_t {
    stream_t* parent;
    bool is_dir;
    MediaResp r;

    // directory
    struct MediaDir* dir;

    // file
    struct MediaFile* file;
    int fd;
    unsigned char key[16];
    uint64_t seek_position;
    bool download_finish;
    vlc_thread_t thread;
    struct Context tctx;
};

static int vlc_sd_probe_Open (vlc_object_t *obj) {
    vlc_sd_probe_Add ((struct vlc_probe_t *)obj, PREFIX_SERVICE "_SD", N_("Chall media services"), SD_CAT_INTERNET);
    return VLC_PROBE_CONTINUE;
}

vlc_module_begin()
    set_category( CAT_PLAYLIST )
    set_subcategory( SUBCAT_PLAYLIST_SD )
    set_shortname( N_("Chall") )
    set_description( N_("Chall media services") )
    set_capability( "services_discovery", 0 )
    set_callbacks( OpenSD, CloseSD )
    add_shortcut( PREFIX_SERVICE "_SD" )

    add_submodule()
        set_category( CAT_INPUT )
        set_subcategory( SUBCAT_INPUT_ACCESS )
        set_callbacks( OpenAccess, CloseAccess )
        set_capability( "access", 10 )
        add_shortcut( PREFIX_SERVICE )
        add_string("media-server", DEFAULT_BASE_URL, "media server URL", "Change the media server to retrived the media", false)
        add_string("key-server-addr", DEFAULT_KEYSERVER_ADDRESS, "key server address", "Change the key server address", false)
        add_integer_with_range("key-server-port", DEFAULT_KEYSERVER_PORT, 1, 65535, "media server port", "Change the key server port", false)
        add_string("media-server-login", NULL, "Login", "Login", false)
        add_password("media-server-pass", NULL, "Password", "Password", false)


    VLC_SD_PROBE_SUBMODULE

vlc_module_end()


static int OpenSD( vlc_object_t* sd_this) {

    services_discovery_t *p_sd = ( services_discovery_t* ) sd_this;
    services_discovery_sys_t *p_sys = malloc(sizeof(struct services_discovery_sys_t));

    if (p_sys == NULL) {
        return VLC_ENOMEM;
    }
    p_sys->parent = p_sd;

    p_sd->p_sys = p_sys;
    p_sd->description = vlc_gettext(N_("Chall media services"));

    global_init();

    p_sys->root_item = input_item_NewDirectory("chall:///", "/", ITEM_NET);
    if (p_sys->root_item == NULL) {
        free(p_sys);
        return VLC_ENOMEM;
    }
    input_item_AddOption(p_sys->root_item, "recursive=collapse", VLC_INPUT_OPTION_TRUSTED|VLC_INPUT_OPTION_UNIQUE);
    services_discovery_AddItem(p_sd, p_sys->root_item);

    return VLC_SUCCESS;
}

static void CloseSD( vlc_object_t* sd_this) {

    services_discovery_t *p_sd = ( services_discovery_t* ) sd_this;
    services_discovery_sys_t *p_sys = p_sd->p_sys;

    services_discovery_RemoveItem(p_sd, p_sys->root_item);
    input_item_Release(p_sys->root_item);
    free(p_sys);
    p_sd->p_sys = NULL;
}

static int OpenAccess( vlc_object_t* access_this) {

    stream_t *p_access = ( stream_t* ) access_this;
    access_sys_t *p_sys = malloc(sizeof(struct access_sys_t));

    if (p_sys == NULL) {
        return VLC_ENOMEM;
    }
    p_access->p_sys = p_sys;

    p_sys->parent = p_access;
    p_sys->fd = -1;
    p_sys->download_finish = false;
    p_sys->seek_position = 0;
    global_init();

    int key_server_port = var_CreateGetInteger(p_access, "key-server-port");
    char* key_server_port_str;
    if (asprintf(&key_server_port_str, "%d", key_server_port) == -1) {
        free(p_sys);
        return VLC_ENOMEM;
    }
    char* m_server = var_CreateGetString(p_access, "media-server");
    char* key_server_addr = var_CreateGetString(p_access, "key-server-addr");

    get_context(p_access);

    setContext(&global_ctx.ctx, m_server, key_server_addr, key_server_port_str);
    free(key_server_addr);
    free(key_server_port_str);
    free(m_server);

    char* login = var_CreateGetString(p_access, "media-server-login");
    char* password = var_CreateGetString(p_access, "media-server-pass");
    VMError r;
    if (login == NULL || password == NULL || *login == '\0' || *password == '\0') {
        msg_Info(p_access, "Log as guest");
        r = remote_login(&global_ctx.ctx, NULL, NULL);
    } else {
        msg_Info(p_access, "Log as %s", login);
        r = remote_login(&global_ctx.ctx, login, password);
    }
    free(login);
    free(password);

    if (r != VM_OK) {
        error_VM(r, p_access);
        release_context();
        free(p_sys);
        return VLC_EGENERIC;
    }

    msg_Info(p_access, "Success load library");

    if (!global_ctx.root_index.is_open) {
        MediaResp mr = open_index(&global_ctx.ctx, &global_ctx.root_index);
        if (mr != MEDIA_OK) {
            release_context();
            msg_Err(p_access, "Fail to load index: %d", mr);
            vlc_dialog_display_error(p_access, "Server authentification failed", "Fail to load server index: %d", mr);
            free(p_sys);
            return VLC_EGENERIC;
        }
    }

    p_sys->dir = NULL;
    p_sys->file = NULL;
    MediaResp mr;
    msg_Info(p_access, "Look for %s", p_access->psz_location);
    if (p_access->psz_location[0] == '\0' || p_access->psz_location[strlen(p_access->psz_location) - 1] == '/') {
        p_sys->is_dir = true;
        mr = get_dir(&global_ctx.ctx, &global_ctx.root_index, p_access->psz_location, &p_sys->dir);
    } else {
        p_sys->is_dir = false;
        // try to find a file
        mr = get_file(&global_ctx.ctx, &global_ctx.root_index, p_access->psz_location, &p_sys->file);
        if (mr == MEDIA_PATH_INVALID) {
            p_sys->is_dir = true;
            mr = get_dir(&global_ctx.ctx, &global_ctx.root_index, p_access->psz_location, &p_sys->dir);
        }
    }
    if (mr != MEDIA_OK) {
        release_context();
        error_Media(mr, p_access, (p_access->psz_url != NULL) ? p_access->psz_url : p_access->psz_location);
        free(p_sys);
        return VLC_EGENERIC;
    }
    if (!p_sys->is_dir) {
        mr = get_file_key(&global_ctx.ctx, p_sys->file->ident, p_sys->key);
        if (mr != MEDIA_OK) {
            release_context();
            error_Media(mr, p_access, (p_access->psz_url != NULL) ? p_access->psz_url : p_access->psz_location);
            free(p_sys);
            return VLC_EGENERIC;
        }
        initContext(&p_sys->tctx, global_ctx.ctx.base_addr, NULL, NULL);
        p_sys->tctx.vlc_obj = p_access;
        release_context();

        if ( vlc_clone( &p_sys->thread, DownloadAccess, p_sys, VLC_THREAD_PRIORITY_LOW)) {
            freeContext(&p_sys->tctx);
            free(p_sys);
            return VLC_EGENERIC;
        }
        ACCESS_SET_CALLBACKS(AccessRead, NULL, AccessControl, AccessSeek);
        p_access->pf_readdir = NULL;
    } else {
        release_context();
        ACCESS_SET_CALLBACKS(NULL, NULL, NULL, NULL);
        p_access->pf_readdir = AccessReadDir;
        p_access->pf_control = access_vaDirectoryControlHelper;
    }

    return VLC_SUCCESS;
}

static void CloseAccess( vlc_object_t* access_this) {

    stream_t *p_access = ( stream_t* ) access_this;
    access_sys_t *p_sys = p_access->p_sys;

    if (!p_sys->is_dir) {
        vlc_mutex_lock(&p_sys->tctx.read_mutex);
        p_sys->tctx.stop_download = true;
        vlc_mutex_unlock(&p_sys->tctx.read_mutex);

        vlc_join( p_sys->thread, NULL );

        if (p_sys->fd > 0) {
            close(p_sys->fd);
        }
        freeContext(&p_sys->tctx);
    }

    free(p_access->p_sys);
    p_access->p_sys = NULL;
}

static void *DownloadAccess(void* data) {

    access_sys_t *p_sys = (access_sys_t*) data;

    p_sys->r = download_file_with_key(&p_sys->tctx, p_sys->file->remote_name, p_sys->key, &p_sys->fd);
    vlc_mutex_lock(&p_sys->tctx.read_mutex);
    if (p_sys->tctx.stop_download) {
        vlc_mutex_unlock(&p_sys->tctx.read_mutex);
        return NULL;
    }
    lseek(p_sys->fd, p_sys->seek_position, SEEK_SET);
    p_sys->download_finish = true;
    vlc_mutex_unlock(&p_sys->tctx.read_mutex);
    return NULL;
}

static int AccessSeek(stream_t *p_access, uint64_t pos) {
    access_sys_t *p_sys = p_access->p_sys;

    vlc_mutex_lock(&p_sys->tctx.read_mutex);
    if (p_sys->tctx.stop_download) {
        vlc_mutex_unlock(&p_sys->tctx.read_mutex);
        return VLC_EGENERIC;
    } else if (p_sys->download_finish) {
        if (lseek(p_sys->fd, pos, SEEK_SET) != pos) {
            vlc_mutex_unlock(&p_sys->tctx.read_mutex);
            return VLC_EGENERIC;
        }
        vlc_mutex_unlock(&p_sys->tctx.read_mutex);
        return VLC_SUCCESS;
    } else {
        p_sys->seek_position = pos;
        vlc_mutex_unlock(&p_sys->tctx.read_mutex);
        return VLC_SUCCESS;
    }
}

static ssize_t AccessRead(stream_t *p_access, void *buf, size_t size) {
    access_sys_t *p_sys = p_access->p_sys;

    vlc_mutex_lock(&p_sys->tctx.read_mutex);
    if (p_sys->tctx.stop_download) {
        vlc_mutex_unlock(&p_sys->tctx.read_mutex);
        return 0;
    } else if (p_sys->download_finish) {
        ssize_t read_len = read(p_sys->fd, buf, size);
        vlc_mutex_unlock(&p_sys->tctx.read_mutex);
        if (read_len < 0) {
            return 0;
        }
        return read_len;
    } else {
        if (p_sys->fd == -1) {
            vlc_mutex_unlock(&p_sys->tctx.read_mutex);
            return -1;
        }
        uint64_t pos = lseek(p_sys->fd, 0, SEEK_CUR);
        // check if the position is already feed
        if (p_sys->seek_position > pos) {
            vlc_mutex_unlock(&p_sys->tctx.read_mutex);
            return -1;
        }
        lseek(p_sys->fd, p_sys->seek_position, SEEK_SET);
        ssize_t read_len = read(p_sys->fd, buf, size);
        lseek(p_sys->fd, pos, SEEK_SET);
        p_sys->seek_position += read_len;
        vlc_mutex_unlock(&p_sys->tctx.read_mutex);

        if (read_len < 0) {
            return 0;
        }
        if (read_len == 0) {
            return -1;
        }
        return read_len;
    }
}

static int AccessControl(stream_t *p_access, int query, va_list args) {
    switch (query) {
        case STREAM_CAN_SEEK:
            *va_arg(args, bool *) = true;
            break;
        case STREAM_CAN_FASTSEEK:
        case STREAM_CAN_PAUSE:
        case STREAM_CAN_CONTROL_PACE:
            *va_arg(args, bool *) = false;
            break;
        case STREAM_GET_PTS_DELAY:
            *va_arg(args, int64_t *) = INT64_C(1000) * var_InheritInteger(p_access, "network-caching");
            break;
        default:
            return VLC_EGENERIC;
    }
    return VLC_SUCCESS;
}

static int AccessReadDir(stream_t *p_access, input_item_node_t* item) {
    access_sys_t *p_sys = p_access->p_sys;

    struct vlc_readdir_helper rdh;
    vlc_readdir_helper_init(&rdh, p_access, item);

    for (size_t i = 0; i< p_sys->dir->nb_file; i++) {
        char* path = NULL;
        MediaResp r = get_file_path(&p_sys->dir->files[i], &path);
        if (r != MEDIA_OK) {
            vlc_readdir_helper_finish(&rdh, false);
            return VLC_ENOMEM;
        }
        char* encode_remote = vlc_uri_encode(p_sys->dir->files[i].remote_name);
        if (encode_remote == NULL) {
            free(path);
            vlc_readdir_helper_finish(&rdh, false);
            return VLC_ENOMEM;
        }
        char* full_path;
        if (asprintf(&full_path, PREFIX_SERVICE "://%s?id=%lu&remote_name=%s", path, p_sys->dir->files[i].ident, encode_remote) == -1) {
            free(path);
            free(encode_remote);
            vlc_readdir_helper_finish(&rdh, false);
            return VLC_ENOMEM;
        }

        msg_Info(p_access, "Add File %s", full_path);
        vlc_readdir_helper_additem(&rdh, full_path, NULL, p_sys->dir->files[i].name, ITEM_TYPE_FILE, ITEM_NET_UNKNOWN);
        free(path);
        free(encode_remote);
        free(full_path);
    }

    for (size_t i = 0; i< p_sys->dir->nb_subdir; i++) {
        char* path = NULL;
        MediaResp r = get_dir_path(&p_sys->dir->subdir[i], &path);
        if (r != MEDIA_OK) {
            vlc_readdir_helper_finish(&rdh, false);
            return VLC_ENOMEM;
        }
        char* encode_remote = vlc_uri_encode(p_sys->dir->subdir[i].remote_name);
        if (encode_remote == NULL) {
            free(path);
            vlc_readdir_helper_finish(&rdh, false);
            return VLC_ENOMEM;
        }
        char* full_path;
        if (asprintf(&full_path, PREFIX_SERVICE "://%s?id=%lu&remote_name=%s", path, p_sys->dir->subdir[i].ident, encode_remote) == -1) {
            free(path);
            free(encode_remote);
            vlc_readdir_helper_finish(&rdh, false);
            return VLC_ENOMEM;
        }

        msg_Info(p_access, "Add directory %s", full_path);
        vlc_readdir_helper_additem(&rdh, full_path, NULL, p_sys->dir->subdir[i].name, ITEM_TYPE_DIRECTORY, ITEM_NET_UNKNOWN);
        free(path);
        free(encode_remote);
        free(full_path);
    }

    vlc_readdir_helper_finish(&rdh, true);
    return VLC_SUCCESS;
}
