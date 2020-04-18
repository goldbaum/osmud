#include <glib.h>
#include <glib/gstdio.h>
#include <glib/gprintf.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "common.h"
#include "policy_violation.h"

#define KLOG_BUF_SIZE (16384) /* 16KB */
#define DROPPED_CONNECTION_INDICATOR "DROP(dest wan)"

bool g_policy_violation_initialized = false;
static pthread_t pol_violation_thread;
static char klog_buf[KLOG_BUF_SIZE] = {0};

static bool pol_violation_create_thread(void);


bool policy_violation_init(void)
{
    g_policy_violation_initialized = false;

    logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_POL_VIOLATION, "Initializing policy violation module");

    if (!pol_violation_create_thread())
        goto out_error;

    g_policy_violation_initialized = true;
    return true;

out_error:
    return false;
}


void policy_violation_free(void)
{
    if (!g_policy_violation_initialized)
        return;

    g_policy_violation_initialized = false;

    /* TODO: free thread stuff */
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
    int retval;
    int i;
    int errnum;
    gchar **klog_lines = NULL;

    while (true)
    {
        retval = klogctl(SYSLOG_ACTION_READ, klog_buf, KLOG_BUF_SIZE);
        if (retval == -1)
        {
            errnum = errno;
            logOmsGeneralMessage(OMS_ERROR, OMS_SUBSYS_POL_VIOLATION, "Failed reading kernel log: %s",
                                 strerror(errnum));
        }
        else if (retval > 0)
        {
            klog_lines = g_strsplit(klog_buf, "\n", -1);
            for (i = 0; klog_lines[i] != NULL; i++)
            {
                process_syslog_line(klog_lines[i]);
            }
            g_strfreev(klog_lines);
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