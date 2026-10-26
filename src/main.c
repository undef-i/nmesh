#include "bogon.h"
#include "config.h"
#include "crypto.h"
#include "forward.h"
#include "frag.h"
#include "pkt.h"
#include "gro.h"
#include "loop.h"
#include "mss.h"
#include "packet.h"
#include "replay.h"
#include "route.h"
#include "tap.h"
#include "udp.h"
#include "utils.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

typedef enum
{
  CMD_RUN = 0,
  CMD_STATUS,
  CMD_START,
  CMD_STOP,
  CMD_RESTART,
} CmdMode;

static char *g_pidfile = NULL;
static bool g_pidfile_armed = false;
static int g_start_ready_fd = -1;


static uint64_t
fnv1a64 (const char *s)
{
  uint64_t h = 1469598103934665603ULL;
  for (; s && *s; s++)
    {
      h ^= (uint8_t)*s;
      h *= 1099511628211ULL;
    }
  return h;
}

static char *
str_dup (const char *s)
{
  if (!s)
    return NULL;
  size_t len = strlen (s) + 1U;
  char *out = malloc (len);
  if (!out)
    return NULL;
  memcpy (out, s, len);
  return out;
}

static char *
path_join_dup (const char *base, const char *name)
{
  if (!base || !name)
    return NULL;
  size_t base_len = strlen (base);
  size_t name_len = strlen (name);
  bool need_sep = (base_len > 0 && base[base_len - 1] != '/');
  size_t out_len = base_len + (need_sep ? 1U : 0U) + name_len + 1U;
  char *out = malloc (out_len);
  if (!out)
    return NULL;
  memcpy (out, base, base_len);
  size_t off = base_len;
  if (need_sep)
    {
      out[off++] = '/';
    }
  memcpy (out + off, name, name_len + 1U);
  return out;
}

static char *
readlink_dup (const char *path)
{
  if (!path || !path[0])
    return NULL;
  size_t cap = 128;
  for (;;)
    {
      char *buf = malloc (cap);
      if (!buf)
        return NULL;
      ssize_t n = readlink (path, buf, cap - 1U);
      if (n < 0)
        {
          free (buf);
          return NULL;
        }
      if ((size_t)n < cap - 1U)
        {
          buf[n] = '\0';
          return buf;
        }
      free (buf);
      if (cap > (SIZE_MAX / 2U))
        return NULL;
      cap *= 2U;
    }
}

static char *
cfg_path_abs_dup (const char *in)
{
  if (!in || !in[0])
    return NULL;
  char *rp = realpath (in, NULL);
  if (rp)
    return rp;
  if (in[0] == '/')
    return str_dup (in);
  char *cwd = getcwd (NULL, 0);
  if (!cwd)
    return NULL;
  char *joined = path_join_dup (cwd, in);
  free (cwd);
  if (!joined)
    return NULL;
  rp = realpath (joined, NULL);
  if (rp)
    {
      free (joined);
      return rp;
    }
  return joined;
}

static char *
pidfile_path_dup (const char *cfg_abs)
{
  uint64_t h = fnv1a64 (cfg_abs);
  int n = snprintf (NULL, 0, "/tmp/nmesh-%016llx.pid",
                    (unsigned long long)h);
  if (n <= 0)
    return NULL;
  char *out = malloc ((size_t)n + 1U);
  if (!out)
    return NULL;
  snprintf (out, (size_t)n + 1U, "/tmp/nmesh-%016llx.pid",
            (unsigned long long)h);
  return out;
}

static void
pidfile_cleanup (void)
{
  if (!g_pidfile_armed || !g_pidfile)
    return;
  unlink (g_pidfile);
  free (g_pidfile);
  g_pidfile = NULL;
  g_pidfile_armed = false;
}

static void
start_ready_close (void)
{
  if (g_start_ready_fd >= 0)
    {
      close (g_start_ready_fd);
      g_start_ready_fd = -1;
    }
}

static void
start_stdio_detach (void)
{
  if (!isatty (STDOUT_FILENO) && !isatty (STDERR_FILENO))
    return;
  int devnull = open ("/dev/null", O_RDWR | O_CLOEXEC);
  if (devnull < 0)
    return;
  (void)dup2 (devnull, STDIN_FILENO);
  (void)dup2 (devnull, STDOUT_FILENO);
  (void)dup2 (devnull, STDERR_FILENO);
  if (devnull > STDERR_FILENO)
    close (devnull);
}

static void
start_ready_ok (void)
{
  if (g_start_ready_fd >= 0)
    {
      char ok = 'R';
      (void)write (g_start_ready_fd, &ok, 1);
    }
  start_ready_close ();
  start_stdio_detach ();
}

static void
start_ready_fail (void)
{
  start_ready_close ();
}


static int
pidfile_write (const char *pid_path, pid_t pid, const char *cfg_abs,
               const char *ifname)
{
  int fd = open (pid_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (fd < 0)
    return -1;
  FILE *fp = fdopen (fd, "w");
  if (!fp)
    {
      close (fd);
      unlink (pid_path);
      return -1;
    }
  bool ok = fprintf (fp, "pid=%d\n", (int)pid) >= 0
            && fprintf (fp, "cfg=%s\n", cfg_abs) >= 0
            && fprintf (fp, "ifname=%s\n", ifname) >= 0
            && fclose (fp) == 0;
  if (!ok)
    {
      unlink (pid_path);
      return -1;
    }
  return 0;
}

static int
pidfile_publish (const char *pid_path, pid_t pid, const char *cfg_abs,
                 const char *ifname)
{
  char tmp_path[PATH_MAX];
  if (snprintf (tmp_path, sizeof (tmp_path), "%s.tmp.%d", pid_path,
                (int)getpid ()) >= (int)sizeof (tmp_path))
    return -1;
  if (pidfile_write (tmp_path, pid, cfg_abs, ifname) != 0)
    return -1;
  if (link (tmp_path, pid_path) != 0)
    {
      unlink (tmp_path);
      return -1;
    }
  unlink (tmp_path);
  return 0;
}

static int
pidfile_read (const char *pid_path, pid_t *pid, char ifname[IFNAMSIZ],
              char **cfg_abs_out)
{
  if (cfg_abs_out)
    *cfg_abs_out = NULL;
  FILE *fp = fopen (pid_path, "r");
  if (!fp)
    return errno == ENOENT ? 1 : -1;
  char *line = NULL;
  size_t line_cap = 0;
  pid_t rd_pid = 0;
  bool pid_ok = false;
  char rd_if[IFNAMSIZ] = { 0 };
  char *rd_cfg = NULL;
  while (getline (&line, &line_cap, fp) >= 0)
    {
      char *nl = strchr (line, '\n');
      if (nl)
        *nl = '\0';
      if (strncmp (line, "pid=", 4) == 0)
        {
          char *end = NULL;
          long v = strtol (line + 4, &end, 10);
          pid_ok = end && *end == '\0' && v > 1 && v <= INT_MAX;
          rd_pid = pid_ok ? (pid_t)v : 0;
        }
      else if (strncmp (line, "ifname=", 7) == 0)
        snprintf (rd_if, sizeof (rd_if), "%s", line + 7);
      else if (strncmp (line, "cfg=", 4) == 0)
        {
          free (rd_cfg);
          rd_cfg = str_dup (line + 4);
          if (!rd_cfg && line[4] != '\0')
            {
              free (line);
              fclose (fp);
              return -1;
            }
        }
    }
  free (line);
  fclose (fp);
  if (!pid_ok || !rd_cfg || !rd_cfg[0] || !rd_if[0])
    {
      free (rd_cfg);
      return -1;
    }
  if (pid)
    *pid = rd_pid;
  if (ifname)
    snprintf (ifname, IFNAMSIZ, "%s", rd_if);
  if (cfg_abs_out)
    *cfg_abs_out = rd_cfg;
  else
    free (rd_cfg);
  return 0;
}

static bool
pid_alive (pid_t pid)
{
  if (pid <= 1)
    return false;
  if (kill (pid, 0) == 0)
    return true;
  return errno != ESRCH;
}

static bool
proc_is_nmesh_pid (pid_t pid)
{
  if (pid <= 1)
    return false;
  char exe_link[64];
  snprintf (exe_link, sizeof (exe_link), "/proc/%d/exe", (int)pid);
  char *exe_path = readlink_dup (exe_link);
  if (!exe_path)
    return false;
  const char *base = strrchr (exe_path, '/');
  base = base ? (base + 1) : exe_path;
  bool ok = (strncmp (base, "nmesh", 5) == 0);
  free (exe_path);
  return ok;
}

static bool
proc_pid_cfg_match (pid_t pid, const char *cfg_abs)
{
  if (pid <= 1)
    return false;
  char path[64];
  snprintf (path, sizeof (path), "/proc/%d/cmdline", (int)pid);
  FILE *fp = fopen (path, "r");
  if (!fp)
    return false;
  char buf[4096];
  size_t len = fread (buf, 1, sizeof (buf) - 1, fp);
  fclose (fp);
  if (len == 0)
    return false;
  buf[len] = '\0';
  const char *arg = NULL;
  for (size_t off = 0; off < len;)
    {
      const char *tok = buf + off;
      size_t tlen = strlen (tok);
      if (tlen == 0)
        break;
      if (strcmp (tok, "-c") == 0 && off + tlen + 1 < len)
        arg = tok + tlen + 1;
      off += tlen + 1;
    }
  if (!arg || !arg[0])
    return false;
  char joined[PATH_MAX];
  if (arg[0] == '/')
    {
      if (snprintf (joined, sizeof (joined), "%s", arg)
          >= (int)sizeof (joined))
        return false;
    }
  else
    {
      snprintf (path, sizeof (path), "/proc/%d/cwd", (int)pid);
      char *cwd = readlink_dup (path);
      if (!cwd)
        return false;
      int n = snprintf (joined, sizeof (joined), "%s/%s", cwd, arg);
      free (cwd);
      if (n < 0 || n >= (int)sizeof (joined))
        return false;
    }
  char *rp = realpath (joined, NULL);
  if (rp)
    {
      bool ok = strcmp (rp, cfg_abs) == 0;
      free (rp);
      return ok;
    }
  return strcmp (joined, cfg_abs) == 0;
}

static bool
pid_rec_live (pid_t pid, const char *cfg_abs)
{
  return pid_alive (pid) && proc_is_nmesh_pid (pid)
         && proc_pid_cfg_match (pid, cfg_abs);
}

static bool
wait_pid_exit (pid_t pid, int timeout_ms)
{
  if (pid <= 1)
    return false;
  int pidfd = (int)syscall (SYS_pidfd_open, pid, 0);
  if (pidfd < 0)
    return !pid_alive (pid);
  struct pollfd pfd;
  memset (&pfd, 0, sizeof (pfd));
  pfd.fd = pidfd;
  pfd.events = POLLIN;
  int rc;
  do
    {
      rc = poll (&pfd, 1, timeout_ms);
    }
  while (rc < 0 && errno == EINTR);
  close (pidfd);
  if (rc > 0)
    return true;
  return !pid_alive (pid);
}

static bool
pid_stop_force (pid_t pid)
{
  if (pid <= 1)
    return false;
  if (!pid_alive (pid))
    return true;
  if (kill (pid, SIGTERM) != 0)
    {
      if (errno == ESRCH)
        return true;
      return false;
    }
  if (wait_pid_exit (pid, 3000))
    return true;
  if (kill (pid, SIGKILL) != 0 && errno != ESRCH)
    return false;
  return wait_pid_exit (pid, 1000) || !pid_alive (pid);
}


static int
cmd_stop_run (const char *cfg_abs)
{
  char *pid_path = pidfile_path_dup (cfg_abs);
  if (!pid_path)
    return 1;
  pid_t pid = 0;
  char ifname[IFNAMSIZ] = { 0 };
  char *cfg_from_pid = NULL;
  int rr = pidfile_read (pid_path, &pid, ifname, &cfg_from_pid);
  if (rr == 1)
    {
      fprintf (stderr, "main: no running instance found for %s\n", cfg_abs);
      free (pid_path);
      return 0;
    }
  if (rr != 0)
    {
      unlink (pid_path);
      fprintf (stderr,
               "main: removed malformed pidfile for %s;"
               " no instance signalled\n",
               cfg_abs);
      free (pid_path);
      return 0;
    }
  int rc = 0;
  if (strcmp (cfg_from_pid, cfg_abs) != 0)
    {
      fprintf (stderr, "main: pid %d does not match cfg %s\n", (int)pid,
               cfg_from_pid);
      rc = 1;
    }
  else if (pid_alive (pid) && !pid_rec_live (pid, cfg_abs))
    {
      fprintf (stderr, "main: pid %d does not match cfg %s\n", (int)pid,
               cfg_from_pid);
      rc = 1;
    }
  else if (pid_alive (pid))
    {
      if (pid_stop_force (pid))
        fprintf (stderr, "main: stopped nmesh pid=%d for %s\n", (int)pid,
                 cfg_abs);
      else
        {
          fprintf (stderr, "main: failed to stop pid=%d\n", (int)pid);
          rc = 1;
        }
    }
  else
    {
      fprintf (stderr, "main: instance for %s not running (stale pidfile)\n",
               cfg_abs);
    }
  if (rc == 0)
    {
      tap_iface_cleanup (ifname);
      unlink (pid_path);
    }
  free (cfg_from_pid);
  free (pid_path);
  return rc;
}

static int
pidfile_claim (const char *cfg_abs, const char *ifname)
{
  char *pid_path = pidfile_path_dup (cfg_abs);
  if (!pid_path)
    return -1;
  for (int attempt = 0; attempt < 2; attempt++)
    {
      pid_t old_pid = 0;
      char *old_cfg = NULL;
      int rr = pidfile_read (pid_path, &old_pid, NULL, &old_cfg);
      if (rr == 0)
        {
          bool live = strcmp (old_cfg, cfg_abs) == 0
                      && pid_rec_live (old_pid, cfg_abs);
          free (old_cfg);
          if (live)
            {
              fprintf (stderr, "main: already running pid=%d for %s\n",
                       (int)old_pid, cfg_abs);
              free (pid_path);
              return -1;
            }
          unlink (pid_path);
        }
      else if (rr < 0)
        unlink (pid_path);
      if (pidfile_publish (pid_path, getpid (), cfg_abs, ifname) == 0)
        {
          g_pidfile = pid_path;
          g_pidfile_armed = true;
          atexit (pidfile_cleanup);
          return 0;
        }
    }
  free (pid_path);
  return -1;
}

#define START_RDY_TMO_MS 90000

static int
cmd_start_daemon (const char *cfg_abs, const char *ifname)
{
  int ready_pipe[2] = { -1, -1 };
  if (pipe2 (ready_pipe, O_CLOEXEC) != 0)
    return -1;
  fflush (stdout);
  fflush (stderr);
  pid_t pid = fork ();
  if (pid < 0)
    {
      close (ready_pipe[0]);
      close (ready_pipe[1]);
      return -1;
    }
  if (pid > 0)
    {
      close (ready_pipe[1]);
      struct pollfd pfd;
      memset (&pfd, 0, sizeof (pfd));
      pfd.fd = ready_pipe[0];
      pfd.events = POLLIN;
      int pr;
      do
        {
          pr = poll (&pfd, 1, START_RDY_TMO_MS);
        }
      while (pr < 0 && errno == EINTR);
      char sig = 0;
      ssize_t nr = -1;
      if (pr > 0)
        {
          do
            {
              nr = read (ready_pipe[0], &sig, 1);
            }
          while (nr < 0 && errno == EINTR);
        }
      close (ready_pipe[0]);
      if (nr == 1 && sig == 'R')
        {
          fprintf (stderr, "main: nmesh started pid=%d\n", (int)pid);
          return 1;
        }
      if (pr == 0)
        {
          kill (pid, SIGKILL);
          (void)wait_pid_exit (pid, 1000);
          fprintf (stderr, "main: start timed out for %s\n", cfg_abs);
          return -1;
        }
      (void)wait_pid_exit (pid, 1000);
      fprintf (stderr, "main: background start failed for %s\n", cfg_abs);
      return -1;
    }
  close (ready_pipe[0]);
  if (setsid () < 0)
    _exit (1);
  if (pidfile_claim (cfg_abs, ifname) != 0)
    _exit (1);
  g_start_ready_fd = ready_pipe[1];
  return 0;
}

static int
status_query_run (const Cfg *cfg)
{
  if (!cfg)
    return 1;
  Cry cry_ctx;
  if (cry_init (&cry_ctx, cfg->auth_ibs ? NULL : cfg->psk, cfg->auth_ibs)
      != 0)
    {
      fprintf (stderr, "status: failed to init crypto\n");
      return 1;
    }
  if (cfg->auth_ibs)
    cry_set_ibs (&cry_ctx, cfg->ibs_mpk, cfg->ibs_sk);
  int fd = socket (AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0)
    {
      perror ("status: socket failed");
      cry_free (&cry_ctx);
      return 1;
    }
  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = 250000;
  setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof (tv));
  struct sockaddr_in6 src;
  memset (&src, 0, sizeof (src));
  src.sin6_family = AF_INET6;
  src.sin6_addr = in6addr_loopback;
  src.sin6_port = 0;
  if (bind (fd, (struct sockaddr *)&src, sizeof (src)) < 0)
    {
      perror ("status: bind failed");
      close (fd);
      cry_free (&cry_ctx);
      return 1;
    }
  struct sockaddr_in6 dst;
  memset (&dst, 0, sizeof (dst));
  dst.sin6_family = AF_INET6;
  dst.sin6_addr = in6addr_loopback;
  dst.sin6_port = htons (cfg->port);
  uint32_t req_id = (uint32_t)(sys_ts () ^ (uint64_t)getpid ());
  uint8_t req_buf[UDP_PL_MAX];
  size_t req_len = 0;
  stat_req_bld (&cry_ctx, req_id, NULL, req_buf, &req_len);
  if (sendto (fd, req_buf, req_len, 0, (struct sockaddr *)&dst, sizeof (dst))
      < 0)
    {
      perror ("status: send failed");
      close (fd);
      cry_free (&cry_ctx);
      return 1;
    }
  char *text = NULL;
  uint8_t *seen = NULL;
  uint64_t total_len = 0;
  size_t got_len = 0;
  uint64_t ddl = sys_ts () + 2000ULL;
  while (sys_ts () < ddl)
    {
      uint8_t raw[UDP_PL_MAX];
      ssize_t n = recv (fd, raw, sizeof (raw), 0);
      if (n < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            continue;
          perror ("status: recv failed");
          break;
        }
      PktHdr hdr;
      uint8_t *pt = NULL;
      size_t pt_len = 0;
      if (pkt_dec (&cry_ctx, raw, (size_t)n, NULL, 0, &hdr, &pt, &pt_len) != 0)
        continue;
      if (hdr.pkt_type != PT_STAT_RSP)
        continue;
      uint32_t pkt_req_id = 0;
      uint64_t off = 0;
      uint64_t pkt_total = 0;
      const uint8_t *chunk = NULL;
      size_t chunk_len = 0;
      if (pkt_prs_stat_rsp (pt, pt_len, &pkt_req_id, &off, &pkt_total, &chunk,
                            &chunk_len)
          != 0)
        continue;
      if (pkt_req_id != req_id)
        continue;
      if (!text)
        {
          total_len = pkt_total;
          if (total_len > (uint64_t)(SIZE_MAX - 1U))
            break;
          text = calloc (1, (size_t)total_len + 1U);
          seen = calloc ((size_t)total_len, 1U);
          if (!text || !seen)
            break;
        }
      if (pkt_total != total_len
          || (size_t)off + chunk_len > (size_t)total_len)
        continue;
      memcpy (text + off, chunk, chunk_len);
      for (size_t i = 0; i < chunk_len; i++)
        {
          size_t idx = (size_t)off + i;
          if (seen[idx] == 0)
            {
              seen[idx] = 1;
              got_len++;
            }
        }
      if (got_len >= (size_t)total_len)
        break;
    }
  close (fd);
  if (!text || total_len == 0 || got_len < (size_t)total_len)
    {
      free (seen);
      free (text);
      fprintf (stderr, "status: no response from 127.0.0.1:%u\n", cfg->port);
      cry_free (&cry_ctx);
      return 1;
    }
  fwrite (text, 1, got_len, stdout);
  free (seen);
  free (text);
  cry_free (&cry_ctx);
  return 0;
}

static void
daemon_ready_hnd (void *arg)
{
  (void)arg;
  start_ready_ok ();
}

int
main (int argc, char **argv)
{
  int rc = 1;
  const char *cfg_path = "nmesh.conf";
  CmdMode cmd = CMD_RUN;
  for (int i = 1; i < argc; i++)
    {
      if (strcmp (argv[i], "-c") == 0 && i + 1 < argc)
        {
          cfg_path = argv[++i];
        }
      else if (strcmp (argv[i], "s") == 0 || strcmp (argv[i], "status") == 0)
        {
          cmd = CMD_STATUS;
        }
      else if (strcmp (argv[i], "start") == 0)
        {
          cmd = CMD_START;
        }
      else if (strcmp (argv[i], "stop") == 0)
        {
          cmd = CMD_STOP;
        }
      else if (strcmp (argv[i], "restart") == 0)
        {
          cmd = CMD_RESTART;
        }
      else
        {
          fprintf (stderr, "main: unknown arg: %s\n", argv[i]);
          return 1;
        }
    }

  char *cfg_abs = cfg_path_abs_dup (cfg_path);
  if (!cfg_abs)
    {
      fprintf (stderr, "main: invalid config path: %s\n", cfg_path);
      return 1;
    }
  if (cmd == CMD_STOP)
    {
      rc = cmd_stop_run (cfg_abs);
      free (cfg_abs);
      return rc;
    }
  if (cmd == CMD_RESTART && cmd_stop_run (cfg_abs) != 0)
    {
      free (cfg_abs);
      return 1;
    }

  Cfg cfg;
  if (cfg_load (cfg_abs, &cfg) != 0)
    {
      fprintf (stderr, "main: failed to load config: %s\n", cfg_abs);
      free (cfg_abs);
      return 1;
    }
  bogon_cfg_apply (&cfg);
  if (cmd == CMD_STATUS)
    {
      rc = status_query_run (&cfg);
      cfg_free (&cfg);
      free (cfg_abs);
      return rc;
    }
  if (cmd == CMD_START || cmd == CMD_RESTART)
    {
      int bg_rc = cmd_start_daemon (cfg_abs, cfg.ifname);
      if (bg_rc < 0)
        {
          cfg_free (&cfg);
          free (cfg_abs);
          return 1;
        }
      if (bg_rc > 0)
        {
          cfg_free (&cfg);
          free (cfg_abs);
          return 0;
        }
    }
  else if (pidfile_claim (cfg_abs, cfg.ifname) != 0)
    {
      cfg_free (&cfg);
      free (cfg_abs);
      return 1;
    }

  printf ("main: loaded config from %s\n", cfg_abs);
  uint64_t sid;
  {
    struct timespec t;
    clock_gettime (CLOCK_REALTIME, &t);
    sid = (uint64_t)t.tv_sec ^ ((uint64_t)t.tv_nsec << 32)
          ^ (uint64_t)getpid ();
  }
  g_rnd_st = (uint32_t)(sid ^ (sid >> 32));
  if (g_rnd_st == 0)
    g_rnd_st = 0x6d2b79f5U;
  printf ("main: session id: %016llx\n", (unsigned long long)sid);
  rc = loop_run (cfg_abs, &cfg, sid, daemon_ready_hnd, NULL);
  cfg_free (&cfg);
  free (cfg_abs);
  if (rc != 0 && g_start_ready_fd >= 0)
    start_ready_fail ();
  return rc;
}
