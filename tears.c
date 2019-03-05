/*
* Copyright (c) 2015-2016, 2018 Genome Research Ltd.
*
* Author: Andrew Whitwham <aw7+github@sanger.ac.uk>
*
* This file is part of tears.
*
* tears is free software: you can redistribute it and/or modify it under
* the terms of the GNU General Public License as published by the Free Software
* Foundation; either version 3 of the License, or (at your option) any later
* version.
*
* This program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
* FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
* details.
*
* You should have received a copy of the GNU General Public License along with
* this program. If not, see <http://www.gnu.org/licenses/>.
*/

/*
*
* tears - streaming a file into iRODS
*
* Andrew Whitwham, November 2015
*
*/

#include "tears_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <rodsClient.h>

#define DEFAULT_BUFFER_SIZE 1048576

typedef struct {
    int write_to_irods;
    int buffer_size;
    int verbose;
    int server_set;
    int force_write;
    char* obj_name;
    int needs_disconnect;
} tears_context_t;

void usage_and_exit(char *pname, int exit_code) {
    fprintf(stdout, "Usage: %s [-b bytes -v -d -f] -w /path/to/irods/file < filein \n", pname);
    fprintf(stdout, "    or %s [-b bytes -v -d] [-r] /path/to/irods/file > fileout\n\n", pname);
    fprintf(stdout, "%s, a program to stream data in to or out of iRODS.\n\n", PACKAGE);
    fprintf(stdout, "\t-w\t\twrite to iRODS\n");
    fprintf(stdout, "\t-r\t\tread from iRODS (default)\n");
    fprintf(stdout, "\t-b bytes\tread/write buffer (default %d)\n", DEFAULT_BUFFER_SIZE);
    fprintf(stdout, "\t-v\t\tverbose mode\n");
    fprintf(stdout, "\t-d\t\tuse default server\n");
    fprintf(stdout, "\t-f\t\tforce overwrite of existing file on iRODS\n");
    fprintf(stdout, "\t-h\t\tprint this help\n\n");
    fprintf(stdout, "Version: %s  Author: %s\n", PACKAGE_STRING, PACKAGE_BUGREPORT);
    fprintf(stdout, "Github: %s\n", PACKAGE_URL);
    exit(exit_code);
}


char *get_irods_error_name(int status, int verb) {
    char *subname = 0;
    char *name;
    name = rodsErrorName(status, &subname);

    if (verb) {
        fprintf(stderr, "Extra error message: %s\n", subname);
    }

    return name;
}


void print_irods_error(char *msg, rErrMsg_t *err) {
    char *subname = 0;
    char *name    = rodsErrorName(err->status, &subname);

    fprintf(stderr, "%s name %s (%s) (%d) %s\n", msg, name, subname,
                err->status, err->msg);
}


void error_and_exit(rcComm_t *c, const char *msg, ...) {
    va_list argp;

    va_start(argp, msg);
    vfprintf(stderr, msg, argp);
    va_end(argp);

    if (c) {
        rcDisconnect(c);
    }

    exit(EXIT_FAILURE);
}


int irods_uri_check(char *uri, rodsEnv *env, int verb) {
    char *user = NULL;
    char *zone = NULL;
    char *host = NULL;
    char *port = NULL;

    if (strncmp(uri, "irods:", 6) != 0) {
        if (verb) {
        fprintf(stderr, "No iRODS URI, using default settings.\n");
    }

        return 0;;
    }

    char *auth  = strstr(uri, "//");
    char *tag_start;
    char *port_end;

    if (auth) {
        tag_start = auth + strlen("//");
        port_end  = strchr(tag_start, '/');
    }

    if (!auth || !port_end) {
        fprintf(stderr, "URI format needed: irods://[irodsUserName%%23irodsZone@][irodsHost][:irodsPort]/collection_path/data_object\n");
    return -1;
    }

    // look for the user name
    char *tag_end = strstr(uri, "%23");

    if (tag_end) {
        user = strndup(tag_start, tag_end - tag_start);
    tag_start = tag_end + strlen("%23");
    }

    // look for zone
    tag_end = strchr(uri, '@');

    if (tag_end) {
    zone = strndup(tag_start, tag_end - tag_start);
    tag_start = tag_end + 1;
    }

    // now the host and port
    tag_end = strchr(auth, ':');
    char *host_tag = tag_end + 1;

    if (tag_end) {
    host = strndup(tag_start, tag_end - tag_start);
    port = strndup(host_tag, port_end - host_tag);
    } else {
    host = strndup(tag_start, port_end - tag_start);
    }

    if (!host) {
        fprintf(stderr, "Error: invalid uri (no host): %s\n", uri);
    return -1;
    }

    // copy of the changed values
    if (user) {
        strncpy(env->rodsUserName, user, NAME_LEN);
    }

    if (zone) {
        strncpy(env->rodsZone, zone, NAME_LEN);
    }

    if (host) {
        strncpy(env->rodsHost, host, NAME_LEN);
    }

    if (port) {
        env->rodsPort = atoi(port);
    }

    // rewrite so just the file is left
    char *file = strdup(port_end);

    if (file) {
        strcpy(uri, file);
    } else {
        fprintf(stderr, "Error: unable to extract file name %s\n", uri);
    return -1;
    }

    if (verb) {
        fprintf(stderr, "File name is %s\n", uri);
    }

    free(file);
    free(user);
    free(zone);
    free(host);
    free(port);

    // success
    return 1;
}


int connect_to_server(
    rcComm_t** conn,
    const char *host,
    const rodsEnv *irods_env,
    const int verbose) {

    rErrMsg_t err_msg;
    int status = 0;
    rcComm_t* new_conn = NULL;
    // make the irods connections
    new_conn = rcConnect(host, irods_env->rodsPort,
                     irods_env->rodsUserName, irods_env->rodsZone,
                     0, &err_msg);

    if (!new_conn) {
        return err_msg.status;
    }

    #if IRODS_VERSION_INTEGER && IRODS_VERSION_INTEGER >= 4001008
        status = clientLogin(new_conn, "", "");
    #else
        status = clientLogin(new_conn);
    #endif

    if (status < 0) {
        rcDisconnect(new_conn);
        error_and_exit(new_conn, "Error: clientLogin failed with status %d:%s\n", status, get_irods_error_name(status, verbose));
    } else {
        if (verbose) {
            fprintf(stderr, "Disconnecting from current conn and using new conn\n");
        }

        // disconnect old connection handle
        if (conn && *conn && ctx->needs_disconnect) {
            //if (verbose) {
                //fprintf(stderr, "disconnecting conn at %p\n", *conn);
            //}
            status = rcDisconnect(*conn);
            //if (status < 0) {
                //fprintf(stderr, "disconnecting conn at %p failed with status %d\n", *conn, status);
            //}
        }

        if (verbose) {
            fprintf(stderr, "Swapping *conn with new_conn at %p\n", new_conn);
        }
        *conn = new_conn;
    }
    return 0;
}


int choose_server(
    rcComm_t** conn,
    dataObjInp_t* data_obj,
    const rodsEnv *irods_env,
    tears_context_t* ctx) {
    int status = 0;
    char* new_host = NULL;
    if (ctx->write_to_irods) {
         if ((status = rcGetHostForPut(*conn, data_obj, &new_host)) < 0) {
             fprintf(stderr, "Error: rcGetHostForPut failed with status %d:%s\n", status, get_irods_error_name(status, ctx->verbose));
            free(new_host);
             return status;
         }
    } else {
         if ((status = rcGetHostForGet(*conn, data_obj, &new_host)) < 0) {
             fprintf(stderr, "Error: rcGetHostForGet failed with status %d:%s\n", status, get_irods_error_name(status, ctx->verbose));
            free(new_host);
             return status;
         }
    }
    if (new_host && strcmp(new_host, THIS_ADDRESS)) {
        if (ctx->verbose) {
            fprintf(stderr, "Chosen server is: %s\n", new_host);
        }

        int status = connect_to_server(conn, new_host, irods_env, ctx->verbose);
        if (status) {
            fprintf(stderr, "Error: rcReconnect failed with status %d.  Continuing with original server.\n", status);
        }
    }
    free(new_host);
    return 0;
}


int open_or_create_data_object(
    rcComm_t** conn,
    const rodsEnv* irods_env,
    const unsigned long offset_in_bytes,
    const tears_context_t* ctx,
    int (*open_func)(rcComm_t*, dataObjInp_t*)) {

    int open_fd = 0;

    // set up the data object
    dataObjInp_t data_obj;
    memset(&data_obj, 0, sizeof(data_obj));
    strncpy(data_obj.objPath, ctx->obj_name, MAX_NAME_LEN);
    if (ctx->write_to_irods) {
        data_obj.openFlags = O_WRONLY;
    } else {
        data_obj.openFlags = O_RDONLY;
    }
    data_obj.dataSize = 0;

    if (!ctx->server_set) {
        int status = choose_server(conn, &data_obj, irods_env, ctx->verbose);
        if (status < 0) {
            error_and_exit(new_conn, "Error: choosing server failed with status %d\n", status, get_irods_error_name(status, ctx->verbose));
        }
    }

    if (ctx->force_write) {
        addKeyVal(&data_obj.condInput, FORCE_FLAG_KW, "");
    }

    if ((open_fd = open_func(*conn, &data_obj)) < 0) {
        fprintf(stderr, "Error: rcGetHostForGet failed with status %d:%s\n", open_fd, get_irods_error_name(open_fd, ctx->verbose));
        return open_fd;
    }

    if (offset_in_bytes) {
        openedDataObjInp_t dataObjLseekInp;
        fileLseekOut_t *dataObjLseekOut = NULL;
        memset(&dataObjLseekInp, 0, sizeof(dataObjLseekInp));
        dataObjLseekInp.whence = SEEK_SET;
        dataObjLseekInp.l1descInx = open_fd;
        dataObjLseekInp.offset = offset_in_bytes;
        int status = 0;
        if (status = rcDataObjLseek(*conn, &dataObjLseekInp, &dataObjLseekOut) < 0) {
            fprintf(stderr, "Error: rcDataObjLseek in file failed with status %d:%s\n", open_fd, get_irods_error_name(open_fd, ctx->verbose));
            return status;
        } else if (dataObjLseekOut) {
            free(dataObjLseekOut);
        }
    }

    return open_fd;
}

int create_data_object(
    rcComm_t** conn,
    const rodsEnv* irods_env,
    const tears_context_t* ctx) {

    int open_fd = open_or_create_data_object(conn, irods_env, 0, ctx, rcDataObjCreate);
    if (open_fd < 0) {
        error_and_exit(*conn, "Error: Creating file failed with status %d:%s\n", open_fd, get_irods_error_name(open_fd, ctx->verbose));
    }
    return open_fd;
}


int open_data_object(
    rcComm_t** conn,
    const rodsEnv* irods_env,
    const unsigned long offset_in_bytes,
    const tears_context_t* ctx) {

    int open_fd = open_or_create_data_object(conn, irods_env, offset_in_bytes, ctx, rcDataObjOpen);
    if (open_fd < 0) {
        error_and_exit(*conn, "Error: Opening file failed with status %d:%s\n", open_fd, get_irods_error_name(open_fd, ctx->verbose));
    }
    return open_fd;
}


int main (int argc, char **argv) {
    rcComm_t           *conn = NULL;
    rodsEnv            irods_env;
    rErrMsg_t          err_msg;
    openedDataObjInp_t open_obj;
    int                open_fd;

    int status;
    char *buffer;
    char prog_name[255];
    int opt;
    unsigned long total_written = 0;

    tears_context_t ctx;
    memset(ctx, 0, sizeof(ctx));
    ctx.buf_size = DEFAULT_BUFFER_SIZE;

    while ((opt = getopt(argc, argv, "b:vhrdwf")) != -1) {
        switch (opt) {
        case 'b':
            ctx.buf_size = atoi(optarg);

            if (ctx.buf_size <= 0) {
                error_and_exit(conn, "Error: buffer size must be greater than 0.\n");
            }

            break;

        case 'v':
            ctx.verbose = 1;
            break;

        case 'r':
            ctx.write_to_irods = 0;
            break;

        case 'w':
            ctx.write_to_irods = 1;
            break;

        case 'd':
            ctx.server_set = 1;
            break;

        case 'f':
            ctx.force_write = 1;
            break;

        case 'h':
            usage_and_exit(argv[0], EXIT_SUCCESS);
            break;

        default:
            usage_and_exit(argv[0], EXIT_FAILURE);
            break;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Error: Missing iRODS file.\n");
        usage_and_exit(argv[0], EXIT_FAILURE);
    }

    ctx.obj_name = argv[optind];

    if ((buffer = malloc(ctx.buf_size)) == NULL) {
        error_and_exit(conn, "Error: unable to set buffer to size %ld\n", ctx.buf_size);
    }

    // set the client name so iRODS knows what program is connecting to it
    sprintf(prog_name, "%s:%s", PACKAGE_NAME, PACKAGE_VERSION);

    if (ctx.verbose) {
        fprintf(stderr, "Setting client name to: %s\n", prog_name);
    }

    setenv(SP_OPTION, prog_name, 1);

    // lets get the irods environment
    if ((status = getRodsEnv(&irods_env)) < 0) {
        error_and_exit(conn, "Error: getRodsEnv failed with status %d:%s\n", status, get_irods_error_name(status, ctx.verbose));
    }

    if ((status = irods_uri_check(ctx.obj_name, &irods_env, ctx.verbose)) < 0) {
        error_and_exit(conn, "Error: invalid uri: %s\n", ctx.obj_name);
    } else if (status > 0) {
        ctx.server_set = 1;
    }

    if (ctx.verbose) {
        fprintf(stderr, "host %s\nzone %s\nuser %s\nport %d\n",
        irods_env.rodsHost, irods_env.rodsZone,
        irods_env.rodsUserName, irods_env.rodsPort);
    }

    #if IRODS_VERSION_INTEGER && IRODS_VERSION_INTEGER >= 4001008
        init_client_api_table();
    #endif

    ctx.needs_disconnect = 1;
    status = connect_to_server(&conn, irods_env.rodsHost, &irods_env, ctx.verbose);
    if (status < 0) {
        error_and_exit(conn, "Error: failed connecting to server with status %d\n", status);
    }

    if (ctx.write_to_irods) {
        open_fd = create_data_object(&conn, &irods_env, &ctx);
    } else {
        open_fd = open_data_object(&conn, &irods_env, total_written, &ctx);
    }

    if (ctx.verbose) {
        fprintf(stderr, "open_fd == %d\n", open_fd);
    }


    ctx.needs_disconnect = 0;

    // the read/write loop
    while (1) {
        bytesBuf_t data_buffer;
        long read_in;
        long written_out;

        // set up common data elements
        memset(&open_obj, 0, sizeof(open_obj));
        open_obj.l1descInx = open_fd;
        data_buffer.buf = buffer;

        // time to read something
        if (ctx.write_to_irods) {
            read_in         = fread(buffer, 1, ctx.buf_size, stdin);
            open_obj.len    = read_in;
            data_buffer.len = open_obj.len;
        } else {
            open_obj.len = ctx.buf_size;
            data_buffer.len = open_obj.len;

            if ((read_in = rcDataObjRead(conn, &open_obj, &data_buffer)) < 0) {
                // Agent fell over - reconnect, seek to total written and try again
                if (SYS_HEADER_READ_LEN_ERR == read_in ||
                    (read_in <= SYS_SOCK_READ_ERR && read_in >= SYS_SOCK_READ_ERR - 999)) {
                    connect_to_server(&conn, irods_env.rodsHost, &irods_env, ctx.verbose);
                    open_fd = open_data_object(&conn, &irods_env, total_written, &ctx);
                    fseek(stdout, total_written, SEEK_SET);
                    continue;
                }
                error_and_exit(conn, "Error:  rcDataObjRead failed with status %ld:%s\n", read_in, get_irods_error_name(read_in, ctx.verbose));
            }
        }

        if (ctx.verbose) {
            fprintf(stderr, "%ld bytes read\n", read_in);
        }

        if (!read_in) break;

        // now try and write something
        if (ctx.write_to_irods) {
            open_obj.len = read_in;
            data_buffer.len = open_obj.len;

            if ((written_out = rcDataObjWrite(conn, &open_obj, &data_buffer)) < 0) {
                // Agent fell over - reconnect, seek to total written and try again
                if (SYS_HEADER_READ_LEN_ERR == written_out ||
                    (written_out <= SYS_SOCK_READ_ERR && written_out >= SYS_SOCK_READ_ERR - 999)) {
                    connect_to_server(&conn, irods_env.rodsHost, &irods_env, ctx.verbose);
                    open_fd = open_data_object(&conn, &irods_env, total_written, &ctx);
                    fseek(stdin, total_written, SEEK_SET);
                    continue;
                }
                error_and_exit(conn, "Error:  rcDataObjWrite failed with status %ld\n", written_out, get_irods_error_name(written_out, ctx.verbose));
            }
        } else {
            written_out = fwrite(buffer, 1, read_in, stdout);
        }

        if (ctx.verbose) {
            fprintf(stderr, "%ld bytes written\n", written_out);
        }

        total_written += written_out;

        if (read_in != written_out) {
            error_and_exit(conn, "Error: write fail %ld written, should be %ld.\n", written_out, read_in);
        }
    };

    if (ctx.verbose) {
        fprintf(stderr, "Total bytes written %ld\n", total_written);
    }

    if ((status = rcDataObjClose(conn, &open_obj)) < 0) {
        error_and_exit(conn, "Error: rcDataObjClose failed with status %d:%s\n", status, get_irods_error_name(status, ctx.verbose));
    }

    rcDisconnect(conn);
    free(buffer);
    exit(EXIT_SUCCESS);
}
