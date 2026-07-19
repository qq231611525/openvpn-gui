/*
 *  dns_update.c -- DNS TXT record update for OpenVPN configuration
 *
 *  Queries wuyue.qq231611525.tk TXT record to get server IP:PORT,
 *  then updates the first config file's "remote" line and auto-reconnects.
 *
 *  Copyright (C) 2025 Nova (ZOO)
 */

#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <shellapi.h>
#include <shlobj.h>

#include "main.h"
#include "misc.h"
#include "openvpn-gui-res.h"
#include "tray.h"

extern options_t o;
extern void StartOpenVPN(connection_t *c);

/* DNS hostname to query */
static const WCHAR DNS_HOST[] = L"wuyue.qq231611525.tk";

/*
 * Safe call to LoadLocalizedString from resource DLL.
 * Returns a heap-allocated WCHAR* the caller must free.
 */
static WCHAR *LoadStringAlloc(UINT id)
{
    WCHAR *buf = NULL;
    int len = LoadString(o.hInstance, id, (LPWSTR)&buf, 0);
    if (len > 0 && buf)
    {
        WCHAR *copy = wcsdup(buf);
        return copy;
    }
    WCHAR *empty = calloc(2, sizeof(WCHAR));
    return empty;
}

/*
 * Safely close a HANDLE if it is not NULL and not INVALID_HANDLE_VALUE.
 */
static void SafeCloseHandle(HANDLE *ph)
{
    if (ph && *ph && *ph != INVALID_HANDLE_VALUE)
    {
        CloseHandle(*ph);
        *ph = NULL;
    }
}

/*
 * ResolveDnsTxtRecord -- Run nslookup and extract the quoted TXT value.
 *   On success: ip_out, port_out are filled (caller frees with free())
 *   Returns TRUE on success, FALSE on failure.
 */
static BOOL ResolveDnsTxtRecord(WCHAR *ip_out, int ip_len,
                                WCHAR *port_out, int port_len)
{
    BOOL ok = FALSE;
    HANDLE hRead = NULL, hWrite = NULL;
    HANDLE hReadErr = NULL, hWriteErr = NULL;
    HANDLE hProcess = NULL;
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

    /* Create a pipe for nslookup stdout */
    if (!CreatePipe(&hRead, &hWrite, &sa, 0))
        goto cleanup;
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    /* Create a pipe for nslookup stderr (discard) */
    if (!CreatePipe(&hReadErr, &hWriteErr, &sa, 0))
        goto cleanup;
    SetHandleInformation(hReadErr, HANDLE_FLAG_INHERIT, 0);

    /* Build command: %SystemRoot%\System32\nslookup.exe -type=TXT <host> */
    WCHAR exe[MAX_PATH];
    if (!GetSystemDirectoryW(exe, _countof(exe)))
        goto cleanup;
    wcscat_s(exe, _countof(exe), L"\\nslookup.exe");

    WCHAR args[512];
    swprintf_s(args, _countof(args), L"nslookup -type=TXT %s", DNS_HOST);

    STARTUPINFOW si = { 0 };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWriteErr;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = { 0 };
    if (!CreateProcessW(exe, args, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW | CREATE_DEFAULT_ERROR_MODE,
                        NULL, NULL, &si, &pi))
        goto cleanup;

    hProcess = pi.hProcess;
    CloseHandle(pi.hThread);

    /* Close our copy of the write handles -- nslookup has them now */
    SafeCloseHandle(&hWrite);
    SafeCloseHandle(&hWriteErr);

    /* Read the output */
    char buffer[4096];
    DWORD total_read = 0;
    DWORD bytes_read;

    while (total_read < sizeof(buffer) - 1)
    {
        if (!ReadFile(hRead, buffer + total_read,
                      (DWORD)(sizeof(buffer) - total_read - 1),
                      &bytes_read, NULL) || bytes_read == 0)
            break;
        total_read += bytes_read;
    }
    buffer[total_read] = '\0';

    /* Wait for nslookup to finish */
    WaitForSingleObject(hProcess, 5000);

    /* Parse output for: TXT = "ip:port" */
    char *p = buffer;
    while (*p)
    {
        if (strncmp(p, "text =", 6) == 0 || strncmp(p, "text=", 5) == 0)
        {
            /* skip to opening quote */
            while (*p && *p != '"')
                p++;
            if (*p == '"')
            {
                p++; /* skip opening quote */
                char *end = strchr(p, '"');
                if (end)
                {
                    int buflen = (int)(end - p);
                    if (buflen > 0 && buflen < 64)
                    {
                        char val[64];
                        memcpy(val, p, buflen);
                        val[buflen] = '\0';

                        /* Extract IP:PORT from val */
                        char *colon = strchr(val, ':');
                        if (colon)
                        {
                            int ip_len_val = (int)(colon - val);
                            wchar_t ip_w[64], port_w[32];

                            MultiByteToWideChar(CP_ACP, 0, val, ip_len_val,
                                                ip_w, _countof(ip_w));
                            ip_w[ip_len_val] = L'\0';

                            MultiByteToWideChar(CP_ACP, 0, colon + 1, -1,
                                                port_w, _countof(port_w));

                            wcsncpy_s(ip_out, ip_len, ip_w, _TRUNCATE);
                            wcsncpy_s(port_out, port_len, port_w, _TRUNCATE);

                            ok = TRUE;
                        }
                    }
                }
            }
            break;
        }
        p++;
    }

cleanup:
    SafeCloseHandle(&hRead);
    SafeCloseHandle(&hWrite);
    SafeCloseHandle(&hReadErr);
    SafeCloseHandle(&hWriteErr);
    SafeCloseHandle(&hProcess);
    return ok;
}

/*
 * Find and replace the "remote ..." line in an OpenVPN config file.
 * If no "remote" line exists, append one just before the first "comp-lzo"
 * or at the end of the file.
 */
static BOOL UpdateConfigRemoteLine(const WCHAR *config_path,
                                   const WCHAR *new_ip, const WCHAR *new_port)
{
    FILE *fp = NULL;
    _wfopen_s(&fp, config_path, L"r, ccs=UTF-8");
    if (!fp)
        return FALSE;

    /* Read entire file */
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    WCHAR *content = malloc((fsize + 2) * sizeof(WCHAR));
    if (!content)
    {
        fclose(fp);
        return FALSE;
    }

    size_t chars_read = fread(content, sizeof(WCHAR), fsize, fp);
    content[chars_read] = L'\0';
    fclose(fp);

    /* Search for existing "remote " line */
    WCHAR remote_line[512] = { 0 };
    WCHAR new_line[512];
    swprintf_s(new_line, _countof(new_line), L"remote %s %s",
               new_ip, new_port);

    BOOL found = FALSE;
    WCHAR *p = content;
    WCHAR *line_start = content;

    while (*p)
    {
        if (*p == L'\n' || *p == L'\r')
        {
            WCHAR saved = *p;
            *p = L'\0';
            WCHAR *line = line_start;

            /* Skip leading whitespace */
            while (*line == L' ' || *line == L'\t')
                line++;

            if (wcsncmp(line, L"remote", 6) == 0 &&
                (line[6] == L' ' || line[6] == L'\t'))
            {
                wcsncpy_s(remote_line, _countof(remote_line), line, _TRUNCATE);
                found = TRUE;
                *p = saved;
                break;
            }
            *p = saved;
            if (*p == L'\r' && p[1] == L'\n')
                p++;
            line_start = p + 1;
        }
        p++;
    }

    /* Build output */
    WCHAR *out = NULL;
    size_t out_cap = 0, out_len = 0;

    #define ENSURE_SPACE(needed) do { \
        if (out_len + (needed) + 1 > out_cap) { \
            out_cap = out_len + (needed) + 4096; \
            out = realloc(out, out_cap * sizeof(WCHAR)); \
        } \
    } while (0)

    size_t content_len = wcslen(content);
    out_cap = content_len + wcslen(new_line) + 4096;
    out = malloc(out_cap * sizeof(WCHAR));
    if (!out)
    {
        free(content);
        return FALSE;
    }
    wcscpy_s(out, out_cap, content);
    out_len = content_len;

    if (found)
    {
        /* Replace remote_line in output with new_line */
        WCHAR *replace_ptr = wcsstr(out, remote_line);
        if (replace_ptr)
        {
            size_t old_len = wcslen(remote_line);
            size_t new_len = wcslen(new_line);

            WCHAR *rest = replace_ptr + old_len;
            size_t rest_len = wcslen(rest);

            memmove(replace_ptr + new_len, rest, (rest_len + 1) * sizeof(WCHAR));
            wmemcpy(replace_ptr, new_line, new_len);
        }
    }
    else
    {
        /* Append new remote line; try to insert before comp-lzo */
        WCHAR *comp_ptr = wcsstr(out, L"comp-lzo");
        if (comp_ptr)
        {
            /* Insert new_line + newline before comp-lzo */
            size_t new_len = wcslen(new_line);
            size_t rest_len = wcslen(comp_ptr);
            WCHAR *rest = comp_ptr;

            memmove(comp_ptr + new_len + 1, rest, (rest_len + 1) * sizeof(WCHAR));
            wmemcpy(comp_ptr, new_line, new_len);
            comp_ptr[new_len] = L'\n';
        }
        else
        {
            /* Append at end */
            WCHAR nl_new[MAX_PATH * 2];
            swprintf_s(nl_new, _countof(nl_new), L"\n%s\n", new_line);
            size_t add_len = wcslen(nl_new);
            ENSURE_SPACE(add_len);
            wcscat_s(out, out_cap, nl_new);
            out_len += add_len;
        }
    }

    free(content);

    /* Write back */
    if (_wfopen_s(&fp, config_path, L"w, ccs=UTF-8") != 0)
    {
        free(out);
        return FALSE;
    }
    fwrite(out, sizeof(WCHAR), wcslen(out), fp);
    fclose(fp);
    free(out);
    return TRUE;
}

/*
 * Show a notification balloon from the tray icon.
 */
static void ShowNotification(const WCHAR *title, const WCHAR *msg, DWORD flags)
{
    NOTIFYICONDATA ni = { 0 };
    ni.cbSize = sizeof(ni);
    ni.uID = 0;
    ni.hWnd = o.hWnd;
    ni.uFlags = NIF_INFO;
    ni.uTimeout = 3000;
    ni.dwInfoFlags = flags;
    wcsncpy_s(ni.szInfoTitle, _countof(ni.szInfoTitle), title, _TRUNCATE);
    wcsncpy_s(ni.szInfo, _countof(ni.szInfo), msg, _TRUNCATE);
    Shell_NotifyIcon(NIM_MODIFY, &ni);
}

/*
 * Check if any connection is currently active.
 */
static BOOL IsConnectionActive(void)
{
    connection_t *c = o.chead;
    while (c)
    {
        if (c->state != disconnected)
            return TRUE;
        c = c->next;
    }
    return FALSE;
}

/*
 * Disconnect the first active connection.
 */
static void DisconnectFirstActive(void)
{
    connection_t *c = o.chead;
    while (c)
    {
        if (c->state != disconnected)
        {
            /* Send SIGTERM to disconnect */
            ManagementCommand(c, "signal SIGTERM", NULL, regular);
            break;
        }
        c = c->next;
    }
}

/*
 * UpdateConfigFromDnsTxt -- main entry point (called from main.c)
 *
 * 1. Show "Querying DNS..." notification
 * 2. Query nslookup TXT record
 * 3. Parse IP:PORT
 * 4. Update first config's remote line
 * 5. Disconnect if active
 * 6. Reconnect to first config
 */
void UpdateConfigFromDnsTxt(void)
{
    WCHAR ip[64] = { 0 };
    WCHAR port[32] = { 0 };

    ShowNotification(L"OpenVPN", LoadStringAlloc(IDS_NFO_DNS_LOOKUP_START),
                     NIIF_INFO);

    if (!ResolveDnsTxtRecord(ip, _countof(ip), port, _countof(port)))
    {
        WCHAR *err = LoadStringAlloc(IDS_NFO_DNS_AUTO_CONNECT_FAILED);
        ShowNotification(L"DNS TXT Error", err, NIIF_ERROR);
        free(err);
        return;
    }

    /* Get first connection config path */
    if (!o.chead)
        return;

    connection_t *first = o.chead;

    /* Build config file path: config_dir\config_file */
    WCHAR config_path[MAX_PATH];
    if (wcslen(first->config_dir) == 0 || wcslen(first->config_file) == 0)
        return;

    swprintf_s(config_path, _countof(config_path), L"%s\\%s",
               first->config_dir, first->config_file);

    if (!UpdateConfigRemoteLine(config_path, ip, port))
    {
        WCHAR *err = LoadStringAlloc(IDS_NFO_DNS_AUTO_CONNECT_FAILED);
        ShowNotification(L"DNS TXT Error", err, NIIF_ERROR);
        free(err);
        return;
    }

    /* Show success */
    WCHAR *ok = LoadStringAlloc(IDS_NFO_DNS_UPDATE_SUCCESS);
    ShowNotification(L"DNS TXT Updated", ok, NIIF_INFO);
    free(ok);

    /* Disconnect if currently active */
    if (IsConnectionActive())
        DisconnectFirstActive();

    /* Brief pause before reconnect */
    Sleep(500);

    /* Reconnect to first config */
    StartOpenVPN(first);
}