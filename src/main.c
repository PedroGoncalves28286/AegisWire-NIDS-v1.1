#define WIN32_LEAN_AND_MEAN

// AegisWire NIDS v1.1.1: Educational sensor, not a production security control.

#include <winsock2.h>
#include <windows.h>
#include <pcap.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WM_LOG (WM_APP + 1)
#define WM_DONE (WM_APP + 2)
#define WM_FINISH (WM_APP + 3)

#define START_ID 2
#define STOP_ID 3
#define CLEAR_ID 4

static const size_t kMaxTrackers = 512;
static const uint64_t kWindowMs = 10000ULL;
static const unsigned int kMaxPortsPerTracker = 64;

typedef struct {
  uint32_t ip;
  uint64_t epoch;
  uint64_t scan_last;
  uint64_t flood_last;
  uint64_t login_last;
  unsigned short ports[64];
  unsigned int n;
  unsigned int syn;
  unsigned int login;
  BOOL used;
} Tracker;

static Tracker table[512];
static HWND win;
static HWND combo;
static HWND edit;
static HWND start;
static HWND stop;
static HWND stats;
static pcap_if_t *devs;
static pcap_t *cap;
static HANDLE worker;
static volatile LONG active;
static volatile LONG stopping;
static volatile LONG packets;
static volatile LONG alerts;
static BOOL closing;

static uint16_t read_u16_be(const unsigned char *data) {
  return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
}

static void log_line(const char *message) {
  size_t size = strlen(message) + 1;
  char *copy = malloc(size);
  if (copy == NULL) {
    return;
  }

  memcpy(copy, message, size);
  if (!PostMessageA(win, WM_LOG, 0, (LPARAM)copy)) {
    free(copy);
  }
}

static void report_alert(const char *kind, uint32_t ip) {
  struct in_addr address;
  char message[256];
  address.s_addr = ip;

  snprintf(message, sizeof(message), "[ALERT] %s from %s\r\n", kind,
           inet_ntoa(address));
  InterlockedIncrement(&alerts);
  log_line(message);
}

// Linear probing avoids replacing another source on a hash collision.
static Tracker *find_tracker(uint32_t ip, uint64_t now) {
  size_t base = (ip ^ (ip >> 16)) % kMaxTrackers;
  size_t oldest = base;
  uint64_t oldest_epoch = UINT64_MAX;

  for (size_t i = 0; i < kMaxTrackers; ++i) {
    size_t slot = (base + i) % kMaxTrackers;
    Tracker *tracker = &table[slot];

    if (tracker->used && tracker->ip == ip) {
      return tracker;
    }

    if (!tracker->used) {
      memset(tracker, 0, sizeof(*tracker));
      tracker->used = TRUE;
      tracker->ip = ip;
      tracker->epoch = now;
      return tracker;
    }

    if (tracker->epoch < oldest_epoch) {
      oldest_epoch = tracker->epoch;
      oldest = slot;
    }
  }

  Tracker *tracker = &table[oldest];
  memset(tracker, 0, sizeof(*tracker));
  tracker->used = TRUE;
  tracker->ip = ip;
  tracker->epoch = now;
  return tracker;
}

static BOOL is_alert_due(uint64_t now, uint64_t last) {
  return !last || now < last || now - last >= kWindowMs;
}

static void process_packet(const struct pcap_pkthdr *header,
                           const unsigned char *data) {
  if (header == NULL || data == NULL) {
    return;
  }

  InterlockedIncrement(&packets);
  size_t length = header->caplen;
  if (length < 14) {
    return;
  }

  size_t offset = 14;
  uint16_t ether_type = read_u16_be(data + 12);

  if (ether_type == 0x8100 || ether_type == 0x88a8) {
    if (length < 18) {
      return;
    }
    ether_type = read_u16_be(data + 16);
    offset = 18;
    if (ether_type == 0x8100 || ether_type == 0x88a8) {
      return;
    }
  }

  if (ether_type != 0x0800 || length - offset < 20) {
    return;
  }

  const unsigned char *ip = data + offset;
  if ((ip[0] >> 4) != 4) {
    return;
  }

  size_t ip_header_size = (size_t)(ip[0] & 15) * 4;
  if (ip_header_size < 20 || ip_header_size > length - offset) {
    return;
  }

  size_t total_length = read_u16_be(ip + 2);
  if (total_length < ip_header_size || total_length > length - offset) {
    return;
  }

  // Fragmented IPv4 packets are ignored until reassembly is implemented.
  if ((read_u16_be(ip + 6) & 0x3fff) != 0 || ip[9] != 6) {
    return;
  }

  size_t tcp_length = total_length - ip_header_size;
  if (tcp_length < 20) {
    return;
  }

  const unsigned char *tcp = ip + ip_header_size;
  size_t tcp_header_size = (size_t)(tcp[12] >> 4) * 4;
  if (tcp_header_size < 20 || tcp_header_size > tcp_length) {
    return;
  }

  uint32_t source_ip;
  memcpy(&source_ip, ip + 12, sizeof(source_ip));

  if (header->ts.tv_sec < 0 || header->ts.tv_usec < 0) {
    return;
  }

  uint64_t now = (uint64_t)header->ts.tv_sec * 1000ULL +
                 (uint64_t)header->ts.tv_usec / 1000ULL;
  Tracker *tracker = find_tracker(source_ip, now);

  if (now < tracker->epoch || now - tracker->epoch >= kWindowMs) {
    uint64_t scan_last = tracker->scan_last;
    uint64_t flood_last = tracker->flood_last;
    uint64_t login_last = tracker->login_last;

    memset(tracker, 0, sizeof(*tracker));
    tracker->used = TRUE;
    tracker->ip = source_ip;
    tracker->epoch = now;
    tracker->scan_last = scan_last;
    tracker->flood_last = flood_last;
    tracker->login_last = login_last;
  }

  uint16_t destination_port = read_u16_be(tcp + 2);

  if ((tcp[13] & 0x12) == 0x02) {
    if (tracker->syn < UINT32_MAX) {
      ++tracker->syn;
    }

    BOOL found = FALSE;
    for (unsigned int i = 0; i < tracker->n; ++i) {
      if (tracker->ports[i] == destination_port) {
        found = TRUE;
        break;
      }
    }

    if (!found && tracker->n < kMaxPortsPerTracker) {
      tracker->ports[tracker->n++] = destination_port;
    }

    if (tracker->n >= 12 && is_alert_due(now, tracker->scan_last)) {
      report_alert("Possible TCP SYN port scan", source_ip);
      tracker->scan_last = now ? now : 1;
    }

    if (tracker->syn >= 150 && is_alert_due(now, tracker->flood_last)) {
      report_alert("Possible SYN burst", source_ip);
      tracker->flood_last = now ? now : 1;
    }
  }

  const unsigned char *payload = tcp + tcp_header_size;
  size_t payload_length = tcp_length - tcp_header_size;

  if ((destination_port == 80 || destination_port == 8080) &&
      ((payload_length >= 11 && memcmp(payload, "POST /login", 11) == 0) ||
       (payload_length >= 12 && memcmp(payload, "POST /signin", 12) == 0))) {
    if (tracker->login < UINT32_MAX) {
      ++tracker->login;
    }

    if (tracker->login >= 5 && is_alert_due(now, tracker->login_last)) {
      report_alert("Possible HTTP login request burst", source_ip);
      tracker->login_last = now ? now : 1;
    }
  }
}

static void packet_callback(unsigned char *user,
                            const struct pcap_pkthdr *header,
                            const unsigned char *data) {
  (void)user;
  if (InterlockedCompareExchange(&active, 0, 0)) {
    process_packet(header, data);
  }
}

static DWORD WINAPI capture_thread(LPVOID unused) {
  (void)unused;
  int result = pcap_loop(cap, -1, packet_callback, NULL);
  if (result == PCAP_ERROR) {
    log_line("[ERROR] Capture loop failed\r\n");
  }
  PostMessageA(win, WM_DONE, 0, 0);
  return 0;
}

static void stop_capture(void) {
  if (worker == NULL || InterlockedExchange(&stopping, 1)) {
    return;
  }

  InterlockedExchange(&active, 0);
  EnableWindow(stop, FALSE);
  if (cap != NULL) {
    pcap_breakloop(cap);
  }
  log_line("[INFO] Stopping capture...\r\n");
}

static void finish_capture(void) {
  if (worker != NULL) {
    if (WaitForSingleObject(worker, 0) != WAIT_OBJECT_0) {
      return;
    }
    CloseHandle(worker);
    worker = NULL;
  }

  if (cap != NULL) {
    pcap_close(cap);
    cap = NULL;
  }

  InterlockedExchange(&active, 0);
  InterlockedExchange(&stopping, 0);
  EnableWindow(start, TRUE);
  EnableWindow(stop, FALSE);
  log_line("[INFO] Capture stopped\r\n");
}

static void start_capture(void) {
  if (worker != NULL || cap != NULL || devs == NULL) {
    return;
  }

  LRESULT index = SendMessageA(combo, CB_GETCURSEL, 0, 0);
  if (index == CB_ERR) {
    return;
  }

  pcap_if_t *device = devs;
  for (LRESULT i = 0; i < index && device != NULL; ++i) {
    device = device->next;
  }
  if (device == NULL) {
    return;
  }

  char error[PCAP_ERRBUF_SIZE] = {0};
  cap = pcap_open_live(device->name, 65535, 1, 500, error);
  if (cap == NULL) {
    MessageBoxA(win, error, "Npcap", MB_ICONERROR);
    return;
  }

  if (pcap_datalink(cap) != DLT_EN10MB) {
    MessageBoxA(win, "Ethernet interfaces only", "AegisWire", MB_ICONWARNING);
    pcap_close(cap);
    cap = NULL;
    return;
  }

  struct bpf_program filter;
  if (pcap_compile(cap, &filter, "(ip and tcp) or (vlan and ip and tcp)",
                   1, PCAP_NETMASK_UNKNOWN) != 0) {
    MessageBoxA(win, pcap_geterr(cap), "BPF compilation failed", MB_ICONERROR);
    pcap_close(cap);
    cap = NULL;
    return;
  }

  if (pcap_setfilter(cap, &filter) != 0) {
    pcap_freecode(&filter);
    MessageBoxA(win, pcap_geterr(cap), "BPF filter failed", MB_ICONERROR);
    pcap_close(cap);
    cap = NULL;
    return;
  }

  pcap_freecode(&filter);
  memset(table, 0, sizeof(table));
  InterlockedExchange(&packets, 0);
  InterlockedExchange(&alerts, 0);
  InterlockedExchange(&stopping, 0);
  InterlockedExchange(&active, 1);

  worker = CreateThread(NULL, 0, capture_thread, NULL, 0, NULL);
  if (worker == NULL) {
    InterlockedExchange(&active, 0);
    pcap_close(cap);
    cap = NULL;
    MessageBoxA(win, "Thread creation failed", "AegisWire", MB_ICONERROR);
    return;
  }

  EnableWindow(start, FALSE);
  EnableWindow(stop, TRUE);
  log_line("[INFO] Capture started\r\n");
}

static LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam,
                                    LPARAM lparam) {
  switch (message) {
    case WM_CREATE: {
      CreateWindowA("STATIC", "Interface:", WS_CHILD | WS_VISIBLE,
                    12, 16, 75, 20, window, 0, 0, 0);
      combo = CreateWindowA("COMBOBOX", "",
                            WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
                            90, 10, 670, 240, window, (HMENU)1, 0, 0);
      start = CreateWindowA("BUTTON", "START", WS_CHILD | WS_VISIBLE,
                            12, 48, 110, 32, window, (HMENU)START_ID, 0, 0);
      stop = CreateWindowA("BUTTON", "STOP",
                           WS_CHILD | WS_VISIBLE | WS_DISABLED,
                           130, 48, 110, 32, window, (HMENU)STOP_ID, 0, 0);
      CreateWindowA("BUTTON", "CLEAR LOG", WS_CHILD | WS_VISIBLE,
                    248, 48, 110, 32, window, (HMENU)CLEAR_ID, 0, 0);
      stats = CreateWindowA("STATIC", "Packets: 0 | Alerts: 0",
                            WS_CHILD | WS_VISIBLE,
                            385, 56, 320, 22, window, 0, 0, 0);
      edit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                             WS_CHILD | WS_VISIBLE | ES_MULTILINE |
                                 ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL,
                             12, 92, 748, 435, window, 0, 0, 0);

      char error[PCAP_ERRBUF_SIZE] = {0};
      if (pcap_findalldevs(&devs, error) == 0) {
        for (pcap_if_t *device = devs; device != NULL;
             device = device->next) {
          SendMessageA(combo, CB_ADDSTRING, 0,
                       (LPARAM)(device->description ? device->description
                                                    : device->name));
        }
        if (devs != NULL) {
          SendMessageA(combo, CB_SETCURSEL, 0, 0);
        }
      } else {
        MessageBoxA(window, error, "Npcap", MB_ICONERROR);
      }

      SetTimer(window, 1, 1000, NULL);
      return 0;
    }

    case WM_COMMAND:
      switch (LOWORD(wparam)) {
        case START_ID:
          start_capture();
          break;
        case STOP_ID:
          stop_capture();
          break;
        case CLEAR_ID:
          SetWindowTextA(edit, "");
          break;
      }
      return 0;

    case WM_TIMER:
      if (wparam == 2 || wparam == 3) {
        if (worker == NULL ||
            WaitForSingleObject(worker, 0) == WAIT_OBJECT_0) {
          KillTimer(window, 2);
          KillTimer(window, 3);
          finish_capture();
          if (closing) {
            DestroyWindow(window);
          }
        }
        return 0;
      }
      {
        char buffer[100];
        snprintf(buffer, sizeof(buffer), "Packets: %ld | Alerts: %ld",
                 InterlockedCompareExchange(&packets, 0, 0),
                 InterlockedCompareExchange(&alerts, 0, 0));
        SetWindowTextA(stats, buffer);
      }
      return 0;

    case WM_LOG: {
      char *line = (char *)lparam;
      if (line != NULL) {
        int length = GetWindowTextLengthA(edit);
        if (length > 120000) {
          SetWindowTextA(edit, "[INFO] Log view truncated\r\n");
        }
        length = GetWindowTextLengthA(edit);
        SendMessageA(edit, EM_SETSEL, length, length);
        SendMessageA(edit, EM_REPLACESEL, 0, (LPARAM)line);
        free(line);
      }
      return 0;
    }

    case WM_DONE:
      InterlockedExchange(&active, 0);
      if (worker != NULL &&
          WaitForSingleObject(worker, 0) != WAIT_OBJECT_0) {
        SetTimer(window, 3, 50, NULL);
      } else {
        finish_capture();
        if (closing) {
          DestroyWindow(window);
        }
      }
      return 0;

    case WM_CLOSE:
      if (worker != NULL) {
        closing = TRUE;
        stop_capture();
        EnableWindow(window, FALSE);
        SetTimer(window, 2, 100, NULL);
        return 0;
      }
      DestroyWindow(window);
      return 0;

    case WM_DESTROY: {
      MSG pending;
      while (PeekMessageA(&pending, window, WM_LOG, WM_LOG, PM_REMOVE)) {
        free((void *)pending.lParam);
      }
      KillTimer(window, 1);
      KillTimer(window, 2);
      KillTimer(window, 3);
      if (devs != NULL) {
        pcap_freealldevs(devs);
      }
      PostQuitMessage(0);
      return 0;
    }
  }

  return DefWindowProcA(window, message, wparam, lparam);
}

int WINAPI WinMain(HINSTANCE instance, HINSTANCE previous_instance,
                   LPSTR arguments, int show_command) {
  (void)previous_instance;
  (void)arguments;

  WSADATA winsock_data;
  if (WSAStartup(MAKEWORD(2, 2), &winsock_data)) {
    return 1;
  }

  WNDCLASSA window_class = {0};
  window_class.lpfnWndProc = window_proc;
  window_class.hInstance = instance;
  window_class.lpszClassName = "AegisWireNative";
  window_class.hCursor = LoadCursor(NULL, IDC_ARROW);
  window_class.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);

  if (!RegisterClassA(&window_class)) {
    WSACleanup();
    return 1;
  }

  win = CreateWindowA("AegisWireNative",
                      "AegisWire NIDS - Experimental v1.1.1",
                      WS_OVERLAPPEDWINDOW, 100, 100, 795, 590,
                      NULL, NULL, instance, NULL);
  if (win == NULL) {
    WSACleanup();
    return 1;
  }

  ShowWindow(win, show_command);
  MSG message;
  while (GetMessageA(&message, NULL, 0, 0) > 0) {
    TranslateMessage(&message);
    DispatchMessageA(&message);
  }

  WSACleanup();
  return 0;
}
