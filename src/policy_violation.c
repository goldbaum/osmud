#include <glib.h>
#include <glib/gstdio.h>
#include <glib/gprintf.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "common.h"
#include "policy_violation.h"

#define MAX_SYSLOG_LINE (2048)
#define DROPPED_CONNECTION_INDICATOR "DROP(dest wan)"

bool g_policy_violation_initialized = false;
static int syslog_fd;
static pthread_t pol_violation_thread;
static char syslog_line[MAX_SYSLOG_LINE] = {0};

static bool pol_violation_create_thread(void);


bool policy_violation_init(const char *syslog_path)
{
    g_policy_violation_initialized = false;

    logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_POL_VIOLATION, "Initializing policy violation module");

    if (!g_file_test(syslog_path, G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR))
    {
        logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_POL_VIOLATION, "System log file doesn't exist (%s)", syslog_path);
        goto err0;
    }

    syslog_fd = open(syslog_path, O_RDONLY);
    if (-1 == syslog_fd)
    {
        logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_POL_VIOLATION, "Failed opening system log file (%s)", syslog_path);
        goto err0;
    }

    /*if (-1 == lseek(syslog_fd, 0, SEEK_END))
    {
        logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_POL_VIOLATION, "Failed seeking system log file (%s)", syslog_path);
        goto err1;
    }*/

    if (!pol_violation_create_thread())
        goto err1;

    g_policy_violation_initialized = true;
    return true;

err1:
    close(syslog_fd);
err0:
    return false;
}


void policy_violation_free(void)
{
    if (!g_policy_violation_initialized)
        return;

    g_policy_violation_initialized = false;

    /* TODO: free thread stuff */
    close(syslog_fd);
    return;
}


static void process_syslog_line(const char *syslog_line)
{
    char *dropped_evt;

    /* check if the line contains a dropped connection to wan */
    dropped_evt = g_strrstr(syslog_line, DROPPED_CONNECTION_INDICATOR);
    if (NULL == dropped_evt)
        return;

    logOmsGeneralMessage(OMS_INFO, OMS_SUBSYS_POL_VIOLATION, "Policy Violation: %s",
                         dropped_evt + strlen(DROPPED_CONNECTION_INDICATOR));
}


static void *pol_violation_thread_func(void *arg)
{
    fd_set rfds;
    struct timeval tv;
    int retval;

    FD_ZERO(&rfds);
    FD_SET(syslog_fd, &rfds);

    /* Wait up to five seconds. */
    tv.tv_sec = 5;
    tv.tv_usec = 0;

    while (true)
    {
        retval = select(syslog_fd + 1, &rfds, NULL, NULL, &tv);
        if (retval == -1)
        {
            perror("select()");
        }
        else if (retval && FD_ISSET(syslog_fd, &rfds))
        {
            logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_POL_VIOLATION, "nfds read: %d", retval);
            retval = osm_read_line(syslog_line, MAX_SYSLOG_LINE, syslog_fd);
            logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_POL_VIOLATION, "readline len: %d", retval);
            if (retval > 1)
            {
                logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_POL_VIOLATION, "syslog line available");
                logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_POL_VIOLATION, syslog_line);
                process_syslog_line(syslog_line);
            }
            else
            {
                logOmsGeneralMessage(OMS_WARN, OMS_SUBSYS_POL_VIOLATION, "No data when reading syslog but expected data.... Returning no data...");
            }
        }
    }

    return NULL;
}


static bool pol_violation_create_thread(void)
{
    int ret;

    ret = pthread_create(&pol_violation_thread, NULL, &pol_violation_thread_func, NULL);
    if(ret != 0)
    {
        logOmsGeneralMessage(OMS_CRIT, OMS_SUBSYS_SNIFFER, "Error creating policy violation thread: %d", ret);
        goto err;
    }

    return true;
err:
    return false;
}