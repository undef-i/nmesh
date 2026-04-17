#include "bogon.h"
#include "config.h"
#include "crypto.h"
#include "forward.h"
#include "frag.h"
#include "gossip.h"
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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <limits.h>
#include <linux/virtio_net.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <termios.h>
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

static char g_pidfile[PATH_MAX];
static bool g_pidfile_armed = false;
static int g_start_ready_fd = -1;
static bool g_daemon_child = false;

#define NMESH_DAEMON_FLAG_ENV "NMESH_DAEMON_CHILD"
#define NMESH_READY_FD_ENV "NMESH_READY_FD"
#define NMESH_PIDFILE_ENV "NMESH_PIDFILE"

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

static int
cfg_path_abs (const char *in, char out[PATH_MAX])
{
  if (!in || !out)
    return -1;
  if (realpath (in, out))
    return 0;
  if (in[0] == '/')
    {
      snprintf (out, PATH_MAX, "%s", in);
      return 0;
    }
  char cwd[PATH_MAX];
  if (!getcwd (cwd, sizeof (cwd)))
    return -1;
  if (snprintf (out, PATH_MAX, "%s/%s", cwd, in) >= PATH_MAX)
    return -1;
  return 0;
}

static void
pidfile_path_get (const char *cfg_abs, char out[PATH_MAX])
{
  uint64_t h = fnv1a64 (cfg_abs);
  snprintf (out, PATH_MAX, "/tmp/nmesh-%016llx.pid", (unsigned long long)h);
}

static void
pidfile_cleanup (void)
{
  if (!g_pidfile_armed)
    return;
  unlink (g_pidfile);
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

static bool
self_exe_get (char out[PATH_MAX])
{
  if (!out)
    return false;
  ssize_t n = readlink ("/proc/self/exe", out, PATH_MAX - 1);
  if (n <= 0 || n >= PATH_MAX)
    return false;
  out[n] = '\0';
  return true;
}

static void
daemon_env_clr (void)
{
  unsetenv (NMESH_DAEMON_FLAG_ENV);
  unsetenv (NMESH_READY_FD_ENV);
  unsetenv (NMESH_PIDFILE_ENV);
}

static int
daemon_env_set (int ready_fd, const char *pid_path)
{
  if (ready_fd < 0 || !pid_path || !pid_path[0])
    return -1;
  int flg = fcntl (ready_fd, F_GETFD, 0);
  if (flg < 0)
    return -1;
  if (fcntl (ready_fd, F_SETFD, flg & ~FD_CLOEXEC) != 0)
    return -1;
  char fd_buf[32];
  snprintf (fd_buf, sizeof (fd_buf), "%d", ready_fd);
  if (setenv (NMESH_DAEMON_FLAG_ENV, "1", 1) != 0)
    return -1;
  if (setenv (NMESH_READY_FD_ENV, fd_buf, 1) != 0)
    return -1;
  if (setenv (NMESH_PIDFILE_ENV, pid_path, 1) != 0)
    return -1;
  return 0;
}

static void
daemon_env_take (void)
{
  const char *flag = getenv (NMESH_DAEMON_FLAG_ENV);
  if (!flag || strcmp (flag, "1") != 0)
    return;
  g_daemon_child = true;
  const char *fd_s = getenv (NMESH_READY_FD_ENV);
  if (fd_s && fd_s[0])
    {
      char *end_ptr = NULL;
      long v = strtol (fd_s, &end_ptr, 10);
      if (end_ptr && *end_ptr == '\0' && v >= 0 && v <= INT_MAX)
        g_start_ready_fd = (int)v;
    }
  const char *pid_path = getenv (NMESH_PIDFILE_ENV);
  if (pid_path && pid_path[0])
    {
      snprintf (g_pidfile, sizeof (g_pidfile), "%s", pid_path);
      g_pidfile_armed = true;
      atexit (pidfile_cleanup);
    }
  daemon_env_clr ();
}

static int
pidfile_write (const char *pid_path, pid_t pid, const char *cfg_abs,
               const char *ifname)
{
  int fd = open (pid_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0)
    return -1;
  FILE *fp = fdopen (fd, "w");
  if (!fp)
    {
      close (fd);
      return -1;
    }
  fprintf (fp, "pid=%d\n", (int)pid);
  fprintf (fp, "cfg=%s\n", cfg_abs ? cfg_abs : "");
  fprintf (fp, "ifname=%s\n", ifname ? ifname : "");
  fclose (fp);
  return 0;
}

static int
pidfile_read (const char *pid_path, pid_t *pid, char ifname[IFNAMSIZ],
              char cfg_abs[PATH_MAX])
{
  FILE *fp = fopen (pid_path, "r");
  if (!fp)
    return -1;
  char line[PATH_MAX + 64];
  pid_t rd_pid = 0;
  char rd_if[IFNAMSIZ] = { 0 };
  char rd_cfg[PATH_MAX] = { 0 };
  while (fgets (line, sizeof (line), fp))
    {
      char *nl = strchr (line, '\n');
      if (nl)
        *nl = '\0';
      if (strncmp (line, "pid=", 4) == 0)
        rd_pid = (pid_t)strtoul (line + 4, NULL, 10);
      else if (strncmp (line, "ifname=", 7) == 0)
        snprintf (rd_if, sizeof (rd_if), "%s", line + 7);
      else if (strncmp (line, "cfg=", 4) == 0)
        snprintf (rd_cfg, sizeof (rd_cfg), "%s", line + 4);
    }
  fclose (fp);
  if (rd_pid <= 1)
    return -1;
  if (pid)
    *pid = rd_pid;
  if (ifname)
    snprintf (ifname, IFNAMSIZ, "%s", rd_if);
  if (cfg_abs)
    snprintf (cfg_abs, PATH_MAX, "%s", rd_cfg);
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
path_abs_base (const char *base_dir, const char *in, char out[PATH_MAX])
{
  if (!base_dir || !base_dir[0] || !in || !in[0] || !out)
    return false;
  if (in[0] == '/')
    {
      if (realpath (in, out))
        return true;
      snprintf (out, PATH_MAX, "%s", in);
      return true;
    }
  char joined[PATH_MAX];
  if (snprintf (joined, sizeof (joined), "%s/%s", base_dir, in)
      >= (int)sizeof (joined))
    return false;
  if (realpath (joined, out))
    return true;
  snprintf (out, PATH_MAX, "%s", joined);
  return true;
}

static ssize_t
proc_cmdline_rd (pid_t pid, char *buf, size_t cap)
{
  if (pid <= 1 || !buf || cap < 2)
    return -1;
  char path[64];
  snprintf (path, sizeof (path), "/proc/%d/cmdline", (int)pid);
  int fd = open (path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return -1;
  ssize_t n = read (fd, buf, cap - 1);
  close (fd);
  if (n <= 0)
    return -1;
  buf[n] = '\0';
  return n;
}

static bool
proc_cwd_get (pid_t pid, char out[PATH_MAX])
{
  if (pid <= 1 || !out)
    return false;
  char path[64];
  snprintf (path, sizeof (path), "/proc/%d/cwd", (int)pid);
  ssize_t n = readlink (path, out, PATH_MAX - 1);
  if (n <= 0)
    return false;
  out[n] = '\0';
  return true;
}

static bool
proc_cfg_path_get (pid_t pid, char out[PATH_MAX])
{
  if (pid <= 1 || !out)
    return false;
  char buf[4096];
  ssize_t n = proc_cmdline_rd (pid, buf, sizeof (buf));
  if (n <= 0)
    return false;
  char cwd[PATH_MAX];
  if (!proc_cwd_get (pid, cwd))
    return false;
  const char *cfg_arg = NULL;
  for (ssize_t i = 0; i < n;)
    {
      const char *arg = buf + i;
      size_t arg_len = strlen (arg);
      if (strcmp (arg, "-c") == 0)
        {
          ssize_t next = i + (ssize_t)arg_len + 1;
          if (next < n)
            cfg_arg = buf + next;
          break;
        }
      i += (ssize_t)arg_len + 1;
    }
  if (!cfg_arg || !cfg_arg[0])
    cfg_arg = "nmesh.conf";
  return path_abs_base (cwd, cfg_arg, out);
}

static bool
proc_is_nmesh_pid (pid_t pid)
{
  if (pid <= 1)
    return false;
  char exe_link[64];
  snprintf (exe_link, sizeof (exe_link), "/proc/%d/exe", (int)pid);
  char exe_path[PATH_MAX];
  ssize_t exe_len = readlink (exe_link, exe_path, sizeof (exe_path) - 1);
  if (exe_len <= 0)
    return false;
  exe_path[exe_len] = '\0';
  const char *base = strrchr (exe_path, '/');
  base = base ? (base + 1) : exe_path;
  return strncmp (base, "nmesh", 5) == 0;
}

static bool
proc_is_nmesh_cfg (pid_t pid, const char *cfg_abs)
{
  if (!proc_is_nmesh_pid (pid) || !cfg_abs || !cfg_abs[0])
    return false;
  char proc_cfg[PATH_MAX];
  if (!proc_cfg_path_get (pid, proc_cfg))
    return false;
  return strcmp (proc_cfg, cfg_abs) == 0;
}

static int
cfg_pid_scan (const char *cfg_abs, pid_t pid_arr[], int cap)
{
  if (!cfg_abs || !pid_arr || cap <= 0)
    return 0;
  DIR *dp = opendir ("/proc");
  if (!dp)
    return 0;
  int cnt = 0;
  struct dirent *ent;
  while ((ent = readdir (dp)) != NULL)
    {
      const char *name = ent->d_name;
      if (!isdigit ((unsigned char)name[0]))
        continue;
      char *end_ptr = NULL;
      unsigned long pv = strtoul (name, &end_ptr, 10);
      if (!end_ptr || *end_ptr != '\0' || pv <= 1 || pv > INT_MAX)
        continue;
      pid_t pid = (pid_t)pv;
      if (pid == getpid ())
        continue;
      if (!proc_is_nmesh_cfg (pid, cfg_abs))
        continue;
      pid_arr[cnt++] = pid;
      if (cnt >= cap)
        break;
    }
  closedir (dp);
  return cnt;
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
  char pid_path[PATH_MAX];
  pidfile_path_get (cfg_abs, pid_path);
  pid_t pid = 0;
  char ifname[IFNAMSIZ] = { 0 };
  char cfg_from_pid[PATH_MAX] = { 0 };
  bool has_pidfile = (pidfile_read (pid_path, &pid, ifname, cfg_from_pid) == 0);
  if (!has_pidfile)
    {
      Cfg cfg;
      if (cfg_load (cfg_abs, &cfg) == 0)
        tap_iface_cleanup (cfg.ifname);
      fprintf (stderr, "main: pidfile missing for %s, scanning /proc\n",
               cfg_abs);
    }
  const char *cfg_id = cfg_from_pid[0] ? cfg_from_pid : cfg_abs;
  int killed_cnt = 0;
  bool pidfile_owned = has_pidfile && strcmp (cfg_id, cfg_abs) == 0
                       && proc_is_nmesh_pid (pid);
  if (pidfile_owned)
    {
      bool was_alive = pid_alive (pid);
      if (pid_stop_force (pid) && was_alive)
        killed_cnt++;
    }
  else if (has_pidfile && pid_alive (pid))
    {
      fprintf (stderr, "main: pid %d does not match cfg %s\n", (int)pid,
               cfg_id);
    }
  pid_t pid_arr[32];
  int scan_cnt = cfg_pid_scan (cfg_abs, pid_arr, 32);
  for (int i = 0; i < scan_cnt; i++)
    {
      if (has_pidfile && pid_arr[i] == pid)
        continue;
      if (pid_stop_force (pid_arr[i]))
        killed_cnt++;
    }
  if (ifname[0] == '\0')
    {
      Cfg cfg;
      if (cfg_load (cfg_abs, &cfg) == 0)
        snprintf (ifname, sizeof (ifname), "%s", cfg.ifname);
    }
  if (ifname[0])
    tap_iface_cleanup (ifname);
  unlink (pid_path);
  if (killed_cnt > 0)
    fprintf (stderr, "main: stopped %d nmesh instance(s) for %s\n", killed_cnt,
             cfg_abs);
  else
    fprintf (stderr, "main: no running instance found for %s\n", cfg_abs);
  return 0;
}

static int
cmd_start_bg (const char *cfg_abs, const char *ifname)
{
  int ready_pipe[2] = { -1, -1 };
  char exe_path[PATH_MAX];
  char pid_path[PATH_MAX];
  pidfile_path_get (cfg_abs, pid_path);
  pid_t old_pid = 0;
  char old_if[IFNAMSIZ] = { 0 };
  char old_cfg[PATH_MAX] = { 0 };
  if (pidfile_read (pid_path, &old_pid, old_if, old_cfg) == 0
      && pid_alive (old_pid) && proc_is_nmesh_pid (old_pid)
      && strcmp ((old_cfg[0] ? old_cfg : cfg_abs), cfg_abs) == 0)
    {
      fprintf (stderr, "main: already running pid=%d for %s\n", (int)old_pid,
               cfg_abs);
      return -1;
    }
  pid_t pid_arr[8];
  int scan_cnt = cfg_pid_scan (cfg_abs, pid_arr, 8);
  if (scan_cnt > 0)
    {
      fprintf (stderr, "main: already running pid=%d for %s\n", (int)pid_arr[0],
               cfg_abs);
      return -1;
    }
  unlink (pid_path);
  if (pipe2 (ready_pipe, O_CLOEXEC) != 0)
    return -1;
  if (!self_exe_get (exe_path))
    {
      close (ready_pipe[0]);
      close (ready_pipe[1]);
      return -1;
    }
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
      char sig = 0;
      ssize_t nr;
      do
        {
          nr = read (ready_pipe[0], &sig, 1);
        }
      while (nr < 0 && errno == EINTR);
      close (ready_pipe[0]);
      if (nr == 1 && sig == 'R')
        {
          fprintf (stderr, "main: nmesh started in background pid=%d\n",
                   (int)pid);
          return 1;
        }
      (void)wait_pid_exit (pid, 1000);
      fprintf (stderr, "main: background start failed for %s\n", cfg_abs);
      return -1;
    }
  close (ready_pipe[0]);
  if (setsid () < 0)
    {
      close (ready_pipe[1]);
      _exit (1);
    }
  signal (SIGHUP, SIG_IGN);
  if (pidfile_write (pid_path, getpid (), cfg_abs, ifname) != 0)
    {
      close (ready_pipe[1]);
      _exit (1);
    }
  if (daemon_env_set (ready_pipe[1], pid_path) != 0)
    {
      close (ready_pipe[1]);
      unlink (pid_path);
      _exit (1);
    }
  char *const child_argv[] = { exe_path, "-c", (char *)cfg_abs, NULL };
  execv (exe_path, child_argv);
  close (ready_pipe[1]);
  unlink (pid_path);
  daemon_env_clr ();
  _exit (1);
}

static int
cmd_start_precheck (const char *cfg_abs)
{
  char pid_path[PATH_MAX];
  pidfile_path_get (cfg_abs, pid_path);
  pid_t old_pid = 0;
  char old_if[IFNAMSIZ] = { 0 };
  char old_cfg[PATH_MAX] = { 0 };
  if (pidfile_read (pid_path, &old_pid, old_if, old_cfg) == 0
      && pid_alive (old_pid) && proc_is_nmesh_pid (old_pid)
      && strcmp ((old_cfg[0] ? old_cfg : cfg_abs), cfg_abs) == 0)
    {
      fprintf (stderr, "main: already running pid=%d for %s\n", (int)old_pid,
               cfg_abs);
      return -1;
    }
  pid_t pid_arr[8];
  int scan_cnt = cfg_pid_scan (cfg_abs, pid_arr, 8);
  if (scan_cnt > 0)
    {
      fprintf (stderr, "main: already running pid=%d for %s\n", (int)pid_arr[0],
               cfg_abs);
      return -1;
    }
  return 0;
}

static int
status_query_run (const Cfg *cfg)
{
  if (!cfg)
    return 1;
  Cry cry_ctx;
  if (cry_init (&cry_ctx, cfg->psk) != 0)
    {
      fprintf (stderr, "status: failed to init crypto\n");
      return 1;
    }
  int fd = socket (AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0)
    {
      perror ("status: socket failed");
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
  stat_req_bld (&cry_ctx, req_id, req_buf, &req_len);
  if (sendto (fd, req_buf, req_len, 0, (struct sockaddr *)&dst, sizeof (dst))
      < 0)
    {
      perror ("status: send failed");
      close (fd);
      return 1;
    }
  char *text = NULL;
  uint16_t total_len = 0;
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
      uint16_t off = 0;
      uint16_t pkt_total = 0;
      const uint8_t *chunk = NULL;
      size_t chunk_len = 0;
      if (gsp_prs_stat_rsp (pt, pt_len, &pkt_req_id, &off, &pkt_total, &chunk,
                            &chunk_len)
          != 0)
        continue;
      if (pkt_req_id != req_id)
        continue;
      if (!text)
        {
          total_len = pkt_total;
          text = calloc (1, (size_t)total_len + 1U);
          if (!text)
            break;
        }
      if (pkt_total != total_len || off != got_len
          || (size_t)off + chunk_len > (size_t)total_len)
        continue;
      memcpy (text + off, chunk, chunk_len);
      got_len += chunk_len;
      if (got_len >= (size_t)total_len)
        break;
    }
  close (fd);
  if (!text || got_len == 0)
    {
      free (text);
      fprintf (stderr, "status: no response from 127.0.0.1:%u\n", cfg->port);
      return 1;
    }
  fwrite (text, 1, got_len, stdout);
  free (text);
  return 0;
}

static void
daemon_ready_hnd (void *arg)
{
  (void)arg;
  if (g_daemon_child)
    start_ready_ok ();
}

int
main (int argc, char **argv)
{
  int rc = 1;
  daemon_env_take ();
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

  char cfg_abs[PATH_MAX];
  if (cfg_path_abs (cfg_path, cfg_abs) != 0)
    {
      fprintf (stderr, "main: invalid config path: %s\n", cfg_path);
      return 1;
    }
  if (cmd == CMD_STOP)
    return cmd_stop_run (cfg_abs);
  if (cmd == CMD_RESTART && cmd_stop_run (cfg_abs) != 0)
    return 1;

  Cfg cfg;
  if (cfg_load (cfg_abs, &cfg) != 0)
    {
      fprintf (stderr, "main: failed to load config: %s\n", cfg_abs);
      return 1;
    }
  bogon_cfg_apply (&cfg);
  if (cmd == CMD_STATUS)
    return status_query_run (&cfg);
  if ((cmd == CMD_START || cmd == CMD_RESTART) && cmd_start_precheck (cfg_abs) != 0)
    return 1;
  if (cmd == CMD_START || cmd == CMD_RESTART)
    {
      int bg_rc = cmd_start_bg (cfg_abs, cfg.ifname);
      if (bg_rc < 0)
        return 1;
      if (bg_rc > 0)
        return 0;
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
  rc = loop_run (cfg_abs, &cfg, sid, g_daemon_child, daemon_ready_hnd, NULL);
  if (rc != 0 && g_daemon_child)
    start_ready_fail ();
  return rc;
}
