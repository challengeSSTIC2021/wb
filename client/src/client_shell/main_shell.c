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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <gcrypt.h>

#include "config.h"
#include "wb_loader.h"
#include "media-client.h"


typedef enum {
    CMD_PARSE_HELP = 0,
    CMD_PARSE_LIST = 1,
    CMD_PARSE_CD = 2,
    CMD_PARSE_EXIT = 3,
    CMD_PARSE_PWD = 4,
    CMD_PARSE_RELOAD = 5,
    CMD_PARSE_GET = 6,
    //CMD_PARSE_DEBUG_PATH = 0x80,
    CMD_PARSE_EMPTY = 0xfd,
    CMD_PARSE_UNKNOW = 0xfe,
    CMD_PARSE_ERROR = 0xff
} CmdType;

struct Command {
    char** args;
    size_t nb_args;
};

static  char* alloc_next_arg(bool *end_cmd, bool *end_input) {
    int current_size = 16;
    char* arg = malloc(16);
    int current_index = 0;
    bool prev_escape = false;
    *end_cmd = false;
    *end_input = false;
    if (arg == NULL) {
        return NULL;
    }
    char c;
    bool stop = false;
    do {
        c = fgetc(stdin);

        if (c == '\0' || c == EOF) {
            stop = true;
            *end_cmd = true;
            *end_input = true;
        } else if (c == '\n') {
            stop = true;
            *end_cmd = true;
            *end_input = false;
        } else if (prev_escape) {
            arg[current_index] = c;
            current_index++;
            prev_escape = false;
        } else if (c == ' ') {
            if (current_index != 0) {
                stop = true;
            }
        } else if (c == '\\') {
            prev_escape = true;
        } else {
            arg[current_index] = c;
            current_index++;
        }
        if (current_index >= current_size) {
            current_size = current_size + 16;
            arg = realloc(arg, current_size);
            if (arg == NULL) {
                return NULL;
            }
        }
    } while (!stop);

    arg[current_index] = '\0';

    return arg;
}

static void free_cmd(struct Command* cmd) {
    if (cmd == NULL) {
        return;
    }
    for (int i = 0; i < cmd->nb_args; i++) {
        if (cmd->args[i] != NULL) {
            free(cmd->args[i]);
            cmd->args[i] = NULL;
        }
    }
    if (cmd->args != NULL) {
        free(cmd->args);
        cmd->args = NULL;
    }
    cmd->nb_args = 0;
}

static  CmdType parse_cmd(struct Command* out, bool* end_input) {
    if (out == NULL) {
        return CMD_PARSE_ERROR;
    }
    free_cmd(out);
    size_t max_args = 4;
    out->args = malloc(sizeof(char*) * max_args);
    out->nb_args = 0;

    if (out->args == NULL) {
        return CMD_PARSE_ERROR;
    }
    out->args[out->nb_args] = NULL;

    bool end_line = false;
    fprintf(stdout, "> ");

    while (!end_line) {
        if (out->nb_args + 1 == max_args) {
            max_args += 4;
            out->args = realloc(out->args, sizeof(char*) * max_args);
            if (out->args == NULL) {
                return CMD_PARSE_ERROR;
            }
        }
        char* next_arg = alloc_next_arg(&end_line, end_input);
        if (next_arg == NULL) {
            return CMD_PARSE_ERROR;
        }
        if (*next_arg != '\0') {
            out->args[out->nb_args] = next_arg;
            out->nb_args++;
            out->args[out->nb_args] = NULL;
        } else {
            free(next_arg);
        }
    }
    if (out->nb_args == 0) {
        return CMD_PARSE_EMPTY;
    }
    if (strcmp(out->args[0], "ls") == 0) {
        return CMD_PARSE_LIST;
    }
    if (strcmp(out->args[0], "help") == 0) {
        return CMD_PARSE_HELP;
    }
    if (strcmp(out->args[0], "cd") == 0) {
        return CMD_PARSE_CD;
    }
    if (strcmp(out->args[0], "exit") == 0) {
        return CMD_PARSE_EXIT;
    }
    if (strcmp(out->args[0], "pwd") == 0) {
        return CMD_PARSE_PWD;
    }
    if (strcmp(out->args[0], "reload") == 0) {
        return CMD_PARSE_RELOAD;
    }
    if (strcmp(out->args[0], "get") == 0) {
        return CMD_PARSE_GET;
    }
    //if (strcmp(out->args[0], "path") == 0) {
    //    return CMD_PARSE_DEBUG_PATH;
    //}

    return CMD_PARSE_UNKNOW;
}

static void cmd_help() {
    fprintf(stdout,
            "   cd <path>                   Change directory\n"
            "   exit                        Exit the programm\n"
            "   get <path> <local_path>     Download a file\n"
            "   help                        Show this help\n"
            "   ls                          List the content of the current directory\n"
            "   pwd                         Print current directory\n"
            "   reload                      Reload the index\n");
}

static void cmd_list(struct Context* ctx, struct MediaDir* current_dir, const struct Command* cmd) {
    if (current_dir == NULL) {
        return;
    }
    struct MediaDir* dir = current_dir;
    MediaResp r = MEDIA_OK;
    const char* path = ".";
    if (cmd->nb_args >= 2) {
        r = get_dir(ctx, current_dir, cmd->args[1], &dir);
        path = cmd->args[1];
    } else if (!dir->is_open) {
        r = open_dir(ctx, dir);
    }
    switch (r) {
        case MEDIA_OK:
            break;
        case MEDIA_PATH_INVALID:
            fprintf(stderr, "Cannot list %s: invalid path\n", path);
            return;
        case MEDIA_WRONG_PERMS:
            fprintf(stderr, "Cannot list %s: permission denied\n", path);
            return;
        case MEDIA_DEBUG_DEVICE:
            fprintf(stderr, "Cannot list %s: need prod device\n", path);
            return;
        case MEDIA_CONNECTION_ERROR:
            fprintf(stderr, "Cannot list %s: connection error\n", path);
            return;
        default:
            fprintf(stderr, "Cannot list %s: error %d\n", path, r);
            return;
    }

    uint64_t perm = get_current_permission(ctx);

    for (size_t i = 0; i < dir->nb_subdir; i++) {
        fprintf(stdout, "d%c-%c %s\n",
                (perm > dir->subdir[i].perm) ?'-':'r',
                (perm > dir->subdir[i].perm) ?'-':'x',
                dir->subdir[i].name);
    }

    for (size_t i = 0; i < dir->nb_file; i++) {
        fprintf(stdout, "-%c-- %s\n",
                (perm > dir->files[i].perm) ?'-':'r',
                dir->files[i].name);
    }
}

static void cmd_get(struct Context* ctx, struct MediaDir* current_dir, const struct Command* cmd) {
    if (current_dir == NULL) {
        return;
    }
    if (cmd->nb_args < 3) {
        fprintf(stderr, "Need two arguments\n");
        return;
    }
    struct MediaFile* f = NULL;
    MediaResp r = get_file(ctx, current_dir, cmd->args[1], &f);
    switch (r) {
        case MEDIA_OK:
            if (f == NULL) {
                fprintf(stderr, "Fail to get %s\n", cmd->args[1]);
                return;
            }
            break;
        case MEDIA_DEBUG_DEVICE:
            fprintf(stderr, "Cannot get %s: need prod device\n", cmd->args[1]);
            return;
        case MEDIA_PATH_INVALID:
            fprintf(stderr, "Cannot get %s: invalid path\n", cmd->args[1]);
            return;
        case MEDIA_WRONG_PERMS:
            fprintf(stderr, "Cannot get %s: permission denied\n", cmd->args[1]);
            return;
        case MEDIA_CONNECTION_ERROR:
            fprintf(stderr, "Cannot get %s: connection error\n", cmd->args[1]);
            return;
        default:
            fprintf(stderr, "Cannot get %s: error %d\n", cmd->args[1], r);
            return;
    }
    int fd = open(cmd->args[2], O_TRUNC | O_CREAT | O_WRONLY, 0644);
    if (fd < 1) {
        fprintf(stderr, "Fail to open %s\n", cmd->args[2]);
        return;
    }
    fprintf(stdout, "Download %s to %s ...\n", cmd->args[1], cmd->args[2]);
    r = download_file(ctx, f, &fd);
    switch (r) {
        case MEDIA_OK:
            break;
        case MEDIA_WRONG_PERMS:
            fprintf(stderr, "Cannot get %s: permission denied\n", cmd->args[1]);
            close(fd);
            unlink(cmd->args[2]);
            return;
        case MEDIA_DEBUG_DEVICE:
            fprintf(stderr, "Cannot get %s: need prod device\n", cmd->args[1]);
            close(fd);
            unlink(cmd->args[2]);
            return;
        case MEDIA_CONNECTION_ERROR:
            fprintf(stderr, "Cannot get %s: connection error\n", cmd->args[1]);
            close(fd);
            unlink(cmd->args[2]);
            return;
        default:
            fprintf(stderr, "Cannot get %s: error %d\n", cmd->args[1], r);
            close(fd);
            unlink(cmd->args[2]);
            return;
    }

    off_t size = lseek(fd, 0, SEEK_END);
    close(fd);
    fprintf(stdout, "Download %s to %s : %zu bytes downloaded\n", cmd->args[1], cmd->args[2], size);
}


int main(int argc, char** argv) {
    gcry_check_version(NULL);
    if (curl_global_init(CURL_GLOBAL_ALL) != 0) abort();
    struct Context ctx;
    initContext(&ctx, getenv("BASE_URL"), getenv("KEYSERVER_ADDR"), getenv("KEYSERVER_PORT"));
    ctx.permcheck = false;

    if (argc >= 3) {
        fprintf(stderr, "[*] Try login to %s" AUTH_API_SUF " ...\n", ctx.base_addr);
        VMError r = remote_login(&ctx, argv[1], argv[2]);
        switch (r) {
            default:
                fprintf(stderr, "[!] Unexpected Error\n");
                freeContext(&ctx);
                return 1;
            case VM_AUTH_FAIL:
                fprintf(stderr, "[!] Login Fail\n");
                freeContext(&ctx);
                return 1;
            case VM_CONNECTION_ERROR:
                fprintf(stderr, "[!] Connection error\n");
                freeContext(&ctx);
                return 1;
            case VM_OK:
                fprintf(stderr, "[+] Login OK\n");
                break;
        }
    } else {
        fprintf(stderr, "[*] Try login at guest to %s" GUEST_API_SUF " ...\n", ctx.base_addr);
        VMError r = remote_login(&ctx, NULL, NULL);
        switch (r) {
            default:
                fprintf(stderr, "[!] Unexpected Error\n");
                freeContext(&ctx);
                return 1;
            case VM_AUTH_FAIL:
                fprintf(stderr, "[!] Login Fail\n");
                freeContext(&ctx);
                return 1;
            case VM_CONNECTION_ERROR:
                fprintf(stderr, "[!] Connection error\n");
                freeContext(&ctx);
                return 1;
            case VM_OK:
                fprintf(stderr, "[+] Login OK\n");
                break;
        }
    }

    fprintf(stderr, "[*] Load index ...\n");
    struct MediaDir root_index = {0};

    MediaResp r = open_index(&ctx, &root_index);
    switch (r) {
        default:
            fprintf(stderr, "[!] Load index fail : %d\n", r);
            freeContext(&ctx);
            return 1;
        case MEDIA_UNKNOW:
            fprintf(stderr, "[!] index not found\n");
            freeContext(&ctx);
            return 1;
        case MEDIA_EMPTY:
            fprintf(stderr, "[!] index empty\n");
            freeContext(&ctx);
            return 1;
        case MEDIA_CONNECTION_ERROR:
            fprintf(stderr, "[!] Connection error\n");
            freeContext(&ctx);
            return 1;
        case MEDIA_OK:
            fprintf(stderr, "[+] Index loaded\n");
            break;
    }

    struct MediaDir* current_dir = &root_index;

    struct Command cmdArgs = {0};
    bool stop = false;

    while (!stop) {
        CmdType cmd = parse_cmd(&cmdArgs, &stop);
        if (!stop) {
            switch (cmd) {
                default:
                    fprintf(stderr, "Missing parser for %d\n", cmd);
                    break;
                case CMD_PARSE_EXIT:
                    stop = true;
                    break;
                case CMD_PARSE_HELP:
                    cmd_help();
                    break;
                case CMD_PARSE_LIST:
                    cmd_list(&ctx, current_dir, &cmdArgs);
                    break;
                case CMD_PARSE_GET:
                    cmd_get(&ctx, current_dir, &cmdArgs);
                    break;
                case CMD_PARSE_RELOAD: {
                    close_index(&root_index);
                    MediaResp r = open_index(&ctx, &root_index);
                    switch (r) {
                        default:
                            fprintf(stderr, "[!] Load index fail : %d\n", r);
                            free_cmd(&cmdArgs);
                            freeContext(&ctx);
                            return 1;
                        case MEDIA_UNKNOW:
                            fprintf(stderr, "[!] index not found\n");
                            free_cmd(&cmdArgs);
                            freeContext(&ctx);
                            return 1;
                        case MEDIA_EMPTY:
                            fprintf(stderr, "[!] index empty\n");
                            free_cmd(&cmdArgs);
                            freeContext(&ctx);
                            return 1;
                        case MEDIA_CONNECTION_ERROR:
                            fprintf(stderr, "[!] connexion error\n");
                            free_cmd(&cmdArgs);
                            freeContext(&ctx);
                            return 1;
                        case MEDIA_OK:
                            fprintf(stderr, "[+] Index reloaded\n");
                            break;
                    }
                    current_dir = &root_index;
                    break;
                }
                case CMD_PARSE_PWD: {
                    char* path = NULL;
                    MediaResp r = get_dir_path(current_dir, &path);
                    if (r == MEDIA_OK && path != NULL) {
                        fprintf(stdout, "%s\n", path);
                    }
                    free(path);
                    break;
                }
                case CMD_PARSE_CD: {
                    if (cmdArgs.nb_args < 2) {
                        fprintf(stderr, "Need a path\n");
                        break;
                    }
                    struct MediaDir* next_dir = NULL;
                    MediaResp r = get_dir(&ctx, current_dir, cmdArgs.args[1], &next_dir);
                    if (r == MEDIA_OK && next_dir != NULL) {
                        current_dir = next_dir;
                        break;
                    }
                    switch (r) {
                        case MEDIA_PATH_INVALID:
                            fprintf(stderr, "Cannot open %s: invalid directory path\n", cmdArgs.args[1]);
                            break;
                        case MEDIA_WRONG_PERMS:
                            fprintf(stderr, "Cannot open %s: permission denied\n", cmdArgs.args[1]);
                            break;
                        case MEDIA_DEBUG_DEVICE:
                            fprintf(stderr, "Cannot open %s: need prod device\n", cmdArgs.args[1]);
                            break;
                        case MEDIA_CONNECTION_ERROR:
                            fprintf(stderr, "Cannot open %s: connexion error\n", cmdArgs.args[1]);
                            break;
                        default:
                            fprintf(stderr, "Cannot open %s: error %d\n", cmdArgs.args[1], r);
                            break;
                    }
                    break;
                }
                case CMD_PARSE_UNKNOW:
                    fprintf(stderr, "Unknow command (%zu args):", cmdArgs.nb_args);
                    for (int i = 0; i<cmdArgs.nb_args; i++) {
                        fprintf(stderr, " '%s'", cmdArgs.args[i]);
                    }
                    fprintf(stderr, "\n");
                    break;
                case CMD_PARSE_ERROR:
                    fprintf(stderr, "[!] error while parsing command\n");
                    return 1;
                case CMD_PARSE_EMPTY:
                    break;
                //case CMD_PARSE_DEBUG_PATH:
                //    if (cmdArgs.nb_args < 2) {
                //        fprintf(stderr, "Need a path argument\n");
                //    } else {
                //        char** p = path_parse(cmdArgs.args[1]);
                //        if (p == NULL) {
                //            fprintf(stderr, "Path parse fail\n");
                //        } else {
                //            fprintf(stdout, "-->");
                //            for (char** t = p; *t != NULL; t++) {
                //                fprintf(stdout, " '%s'", *t);
                //            }
                //            fprintf(stdout, "\n");
                //            free_path_parse(p);
                //        }
                //    }
                //    break;
            }
        }
        free_cmd(&cmdArgs);
    }

    close_index(&root_index);
    freeContext(&ctx);

    return 0;
}
