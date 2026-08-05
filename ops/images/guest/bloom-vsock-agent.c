#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <grp.h>
#include <pty.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/vm_sockets.h>

#define PORT 5000
#define BUFFER_SIZE 262144

static char history[BUFFER_SIZE];
static size_t history_len = 0;

static void remember(const char *data, size_t length) {
  if (history_len + length > BUFFER_SIZE) {
    size_t remove = history_len + length - BUFFER_SIZE;
    memmove(history, history + remove, history_len - remove);
    history_len -= remove;
  }
  memcpy(history + history_len, data, length);
  history_len += length;
}

static int write_all(int fd, const char *data, size_t length) {
  while (length > 0) {
    ssize_t written = write(fd, data, length);
    if (written < 0 && errno == EINTR) continue;
    if (written <= 0) return -1;
    data += written;
    length -= (size_t)written;
  }
  return 0;
}

static int listen_vsock(void) {
  int fd = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return -1;
  struct sockaddr_vm address = {0};
  address.svm_family = AF_VSOCK;
  address.svm_cid = VMADDR_CID_ANY;
  address.svm_port = PORT;
  if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0 || listen(fd, 4) < 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static int start_shell(int *master) {
  pid_t child = forkpty(master, NULL, NULL, NULL);
  if (child < 0) return -1;
  if (child == 0) {
    chdir("/workspace");
    setenv("HOME", "/workspace", 1);
    setenv("ENV", "/etc/ashrc", 1);
    setenv("TERM", "xterm-256color", 1);
    setenv("USER", "workspace", 1);
    setenv("LOGNAME", "workspace", 1);
    if (setgroups(0, NULL) < 0) _exit(126);
    if (setgid(1000) < 0 || setuid(1000) < 0) _exit(126);
    execl("/bin/bash", "bash", "-l", NULL);
    _exit(127);
  }
  return child;
}

int main(void) {
  signal(SIGPIPE, SIG_IGN);
  int listener = listen_vsock();
  if (listener < 0) { perror("vsock listen"); return 1; }
  int master = -1;
  pid_t shell = start_shell(&master);
  if (shell < 0) { perror("forkpty"); return 1; }
  int client = -1;
  const char banner[] = "\r\nBloom vsock terminal ready. Check persistence capabilities; do not enter secrets.\r\n";
  remember(banner, sizeof(banner) - 1);

  for (;;) {
    struct pollfd fds[3] = {
      { .fd = listener, .events = POLLIN },
      { .fd = master, .events = POLLIN },
      { .fd = client, .events = client >= 0 ? POLLIN : 0 },
    };
    int ready = poll(fds, 3, -1);
    if (ready < 0 && errno == EINTR) continue;
    if (ready < 0) break;
    if (fds[0].revents & POLLIN) {
      int next = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
      if (next >= 0) {
        if (client >= 0) close(client);
        client = next;
        if (history_len && write_all(client, history, history_len) < 0) { close(client); client = -1; }
      }
    }
    if (fds[1].revents & (POLLIN | POLLHUP)) {
      char buffer[8192];
      ssize_t count = read(master, buffer, sizeof(buffer));
      if (count > 0) {
        remember(buffer, (size_t)count);
        if (client >= 0 && write_all(client, buffer, (size_t)count) < 0) { close(client); client = -1; }
      } else if (waitpid(shell, NULL, WNOHANG) == shell) {
        close(master);
        shell = start_shell(&master);
        if (shell < 0) break;
      }
    }
    if (client >= 0 && fds[2].revents & (POLLIN | POLLHUP | POLLERR)) {
      char buffer[8192];
      ssize_t count = read(client, buffer, sizeof(buffer));
      if (count > 0) write_all(master, buffer, (size_t)count);
      else { close(client); client = -1; }
    }
  }
  kill(shell, SIGKILL);
  return 1;
}
