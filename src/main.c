#define WIN32_LEAN_AND_MEAN
/* AegisWire NIDS v1.1.1: educational sensor, not a production security control. */
#include <winsock2.h>
#include <windows.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define WM_LOG (WM_APP+1)
#define WM_DONE (WM_APP+2)
#define WM_FINISH (WM_APP+3)
#define TRACKERS 512
#define PERIOD 10000ULL
#define START_ID 2
#define STOP_ID 3
#define CLEAR_ID 4

typedef struct { uint32_t ip; uint64_t epoch,scan_last,flood_last,login_last;
 unsigned short ports[64]; unsigned n,syn,login; BOOL used; } Tracker;
static Tracker table[TRACKERS];
static HWND win,combo,edit,start,stop,stats;
static pcap_if_t *devs;
static pcap_t *cap;
static HANDLE worker;
static volatile LONG active,stopping,packets,alerts;
static BOOL closing;
static uint16_t rd16(const unsigned char *p){return (uint16_t)(((uint16_t)p[0]<<8)|p[1]);}
static void logline(const char *s){size_t n=strlen(s)+1;char *p=malloc(n);if(!p)return;memcpy(p,s,n);if(!PostMessageA(win,WM_LOG,0,(LPARAM)p))free(p);}
static void alert(const char *kind,uint32_t ip){struct in_addr a;char b[256];a.s_addr=ip;snprintf(b,sizeof(b),"[ALERT] %s from %s\r\n",kind,inet_ntoa(a));InterlockedIncrement(&alerts);logline(b);}
/* Linear probing prevents a hash collision from silently replacing another source. */
static Tracker *lookup(uint32_t ip,uint64_t now){size_t base=(ip^(ip>>16))%TRACKERS,oldest=base;uint64_t age=UINT64_MAX;
 for(size_t i=0;i<TRACKERS;i++){size_t slot=(base+i)%TRACKERS;Tracker *t=&table[slot];
 if(t->used&&t->ip==ip)return t;
 if(!t->used){memset(t,0,sizeof(*t));t->used=TRUE;t->ip=ip;t->epoch=now;return t;}
 if(t->epoch<age){age=t->epoch;oldest=slot;}}
 Tracker *t=&table[oldest];memset(t,0,sizeof(*t));t->used=TRUE;t->ip=ip;t->epoch=now;return t;}
static BOOL due(uint64_t now,uint64_t last){return !last||now<last||now-last>=PERIOD;}
static void process(const struct pcap_pkthdr *h,const unsigned char *d){
 if(!h||!d)return;InterlockedIncrement(&packets);size_t n=h->caplen;if(n<14)return;
 size_t off=14;uint16_t et=rd16(d+12);
 if(et==0x8100||et==0x88a8){if(n<18)return;et=rd16(d+16);off=18;if(et==0x8100||et==0x88a8)return;}
 if(et!=0x0800||n-off<20)return;
 const unsigned char *ip=d+off;if((ip[0]>>4)!=4)return;
 size_t ih=(size_t)(ip[0]&15)*4;if(ih<20||ih>n-off)return;
 size_t total=rd16(ip+2);if(total<ih||total>n-off)return;
 /* Fragmented IPv4 packets are ignored until reassembly is implemented. */
 if((rd16(ip+6)&0x3fff)!=0||ip[9]!=6)return;
 size_t left=total-ih;if(left<20)return;const unsigned char *tcp=ip+ih;
 size_t th=(size_t)(tcp[12]>>4)*4;if(th<20||th>left)return;
 uint32_t src;memcpy(&src,ip+12,4);
 if(h->ts.tv_sec<0||h->ts.tv_usec<0)return;
 uint64_t now=(uint64_t)h->ts.tv_sec*1000ULL+(uint64_t)h->ts.tv_usec/1000ULL;
 Tracker *t=lookup(src,now);
 if(now<t->epoch||now-t->epoch>=PERIOD){uint64_t s=t->scan_last,f=t->flood_last,l=t->login_last;
 memset(t,0,sizeof(*t));t->used=TRUE;t->ip=src;t->epoch=now;t->scan_last=s;t->flood_last=f;t->login_last=l;}
 uint16_t port=rd16(tcp+2);
 if((tcp[13]&0x12)==0x02){if(t->syn<UINT32_MAX)t->syn++;BOOL found=FALSE;
 for(unsigned i=0;i<t->n;i++)if(t->ports[i]==port){found=TRUE;break;}
 if(!found&&t->n<64)t->ports[t->n++]=port;
 if(t->n>=12&&due(now,t->scan_last)){alert("Possible TCP SYN port scan",src);t->scan_last=now?now:1;}
 if(t->syn>=150&&due(now,t->flood_last)){alert("Possible SYN burst",src);t->flood_last=now?now:1;}}
 const unsigned char *p=tcp+th;size_t len=left-th;
 if((port==80||port==8080)&&((len>=11&&!memcmp(p,"POST /login",11))||(len>=12&&!memcmp(p,"POST /signin",12)))){
 if(t->login<UINT32_MAX)t->login++;if(t->login>=5&&due(now,t->login_last)){alert("Possible HTTP login request burst",src);t->login_last=now?now:1;}}
}
static void callback(unsigned char *u,const struct pcap_pkthdr *h,const unsigned char *d){(void)u;if(InterlockedCompareExchange(&active,0,0))process(h,d);}
static DWORD WINAPI capture_thread(LPVOID unused){(void)unused;int rc=pcap_loop(cap,-1,callback,NULL);if(rc==PCAP_ERROR)logline("[ERROR] Capture loop failed\r\n");PostMessageA(win,WM_DONE,0,0);return 0;}
static void stop_capture(void){if(!worker||InterlockedExchange(&stopping,1))return;InterlockedExchange(&active,0);EnableWindow(stop,FALSE);if(cap)pcap_breakloop(cap);logline("[INFO] Stopping capture...\r\n");}
static void finish_capture(void){if(worker){if(WaitForSingleObject(worker,0)!=WAIT_OBJECT_0)return;CloseHandle(worker);worker=NULL;}
 if(cap){pcap_close(cap);cap=NULL;}InterlockedExchange(&active,0);InterlockedExchange(&stopping,0);
 EnableWindow(start,TRUE);EnableWindow(stop,FALSE);logline("[INFO] Capture stopped\r\n");}
static void start_capture(void){if(worker||cap||!devs)return;LRESULT idx=SendMessageA(combo,CB_GETCURSEL,0,0);if(idx==CB_ERR)return;
 pcap_if_t *d=devs;for(LRESULT i=0;i<idx&&d;i++)d=d->next;if(!d)return;
 char err[PCAP_ERRBUF_SIZE]={0};cap=pcap_open_live(d->name,65535,1,500,err);
 if(!cap){MessageBoxA(win,err,"Npcap",MB_ICONERROR);return;}
 if(pcap_datalink(cap)!=DLT_EN10MB){MessageBoxA(win,"Ethernet interfaces only","AegisWire",MB_ICONWARNING);pcap_close(cap);cap=NULL;return;}
 struct bpf_program b;if(pcap_compile(cap,&b,"(ip and tcp) or (vlan and ip and tcp)",1,PCAP_NETMASK_UNKNOWN)!=0){MessageBoxA(win,pcap_geterr(cap),"BPF compilation failed",MB_ICONERROR);pcap_close(cap);cap=NULL;return;}
 if(pcap_setfilter(cap,&b)!=0){pcap_freecode(&b);MessageBoxA(win,pcap_geterr(cap),"BPF filter failed",MB_ICONERROR);pcap_close(cap);cap=NULL;return;}
 pcap_freecode(&b);memset(table,0,sizeof(table));InterlockedExchange(&packets,0);InterlockedExchange(&alerts,0);
 InterlockedExchange(&stopping,0);InterlockedExchange(&active,1);
 worker=CreateThread(NULL,0,capture_thread,NULL,0,NULL);
 if(!worker){InterlockedExchange(&active,0);pcap_close(cap);cap=NULL;MessageBoxA(win,"Thread creation failed","AegisWire",MB_ICONERROR);return;}
 EnableWindow(start,FALSE);EnableWindow(stop,TRUE);logline("[INFO] Capture started\r\n");}
static LRESULT CALLBACK wnd(HWND w,UINT msg,WPARAM wp,LPARAM lp){switch(msg){
 case WM_CREATE:{CreateWindowA("STATIC","Interface:",WS_CHILD|WS_VISIBLE,12,16,75,20,w,0,0,0);
 combo=CreateWindowA("COMBOBOX","",WS_CHILD|WS_VISIBLE|CBS_DROPDOWNLIST|WS_VSCROLL,90,10,670,240,w,(HMENU)1,0,0);
 start=CreateWindowA("BUTTON","START",WS_CHILD|WS_VISIBLE,12,48,110,32,w,(HMENU)START_ID,0,0);
 stop=CreateWindowA("BUTTON","STOP",WS_CHILD|WS_VISIBLE|WS_DISABLED,130,48,110,32,w,(HMENU)STOP_ID,0,0);
 CreateWindowA("BUTTON","CLEAR LOG",WS_CHILD|WS_VISIBLE,248,48,110,32,w,(HMENU)CLEAR_ID,0,0);
 stats=CreateWindowA("STATIC","Packets: 0 | Alerts: 0",WS_CHILD|WS_VISIBLE,385,56,320,22,w,0,0,0);
 edit=CreateWindowExA(WS_EX_CLIENTEDGE,"EDIT","",WS_CHILD|WS_VISIBLE|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL|WS_VSCROLL,12,92,748,435,w,0,0,0);
 char err[PCAP_ERRBUF_SIZE]={0};if(pcap_findalldevs(&devs,err)==0){for(pcap_if_t *d=devs;d;d=d->next)SendMessageA(combo,CB_ADDSTRING,0,(LPARAM)(d->description?d->description:d->name));if(devs)SendMessageA(combo,CB_SETCURSEL,0,0);}else MessageBoxA(w,err,"Npcap",MB_ICONERROR);
 SetTimer(w,1,1000,NULL);return 0;}
 case WM_COMMAND:switch(LOWORD(wp)){case START_ID:start_capture();break;case STOP_ID:stop_capture();break;case CLEAR_ID:SetWindowTextA(edit,"");break;}return 0;
 case WM_TIMER:if(wp==2||wp==3){if(!worker||WaitForSingleObject(worker,0)==WAIT_OBJECT_0){KillTimer(w,2);KillTimer(w,3);finish_capture();if(closing)DestroyWindow(w);}return 0;}
 {char b[100];snprintf(b,sizeof(b),"Packets: %ld | Alerts: %ld",InterlockedCompareExchange(&packets,0,0),InterlockedCompareExchange(&alerts,0,0));SetWindowTextA(stats,b);}return 0;
 case WM_LOG:{char *p=(char *)lp;if(p){int n=GetWindowTextLengthA(edit);if(n>120000)SetWindowTextA(edit,"[INFO] Log view truncated\r\n");n=GetWindowTextLengthA(edit);SendMessageA(edit,EM_SETSEL,n,n);SendMessageA(edit,EM_REPLACESEL,0,(LPARAM)p);free(p);}return 0;}
 case WM_DONE:InterlockedExchange(&active,0);if(worker&&WaitForSingleObject(worker,0)!=WAIT_OBJECT_0){SetTimer(w,3,50,NULL);}else{finish_capture();if(closing)DestroyWindow(w);}return 0;
 case WM_CLOSE:if(worker){closing=TRUE;stop_capture();EnableWindow(w,FALSE);SetTimer(w,2,100,NULL);return 0;}DestroyWindow(w);return 0;
 case WM_DESTROY:{MSG pending;while(PeekMessageA(&pending,w,WM_LOG,WM_LOG,PM_REMOVE))free((void *)pending.lParam);}
 KillTimer(w,1);KillTimer(w,2);KillTimer(w,3);if(devs)pcap_freealldevs(devs);PostQuitMessage(0);return 0;
 }return DefWindowProcA(w,msg,wp,lp);}
int WINAPI WinMain(HINSTANCE h,HINSTANCE prev,LPSTR args,int show){(void)prev;(void)args;WSADATA data;if(WSAStartup(MAKEWORD(2,2),&data))return 1;
 WNDCLASSA wc={0};wc.lpfnWndProc=wnd;wc.hInstance=h;wc.lpszClassName="AegisWireNative";wc.hCursor=LoadCursor(NULL,IDC_ARROW);wc.hbrBackground=(HBRUSH)(COLOR_BTNFACE+1);
 if(!RegisterClassA(&wc)){WSACleanup();return 1;}win=CreateWindowA("AegisWireNative","AegisWire NIDS - Experimental v1.1.1",WS_OVERLAPPEDWINDOW,100,100,795,590,NULL,NULL,h,NULL);
 if(!win){WSACleanup();return 1;}ShowWindow(win,show);MSG m;while(GetMessageA(&m,NULL,0,0)>0){TranslateMessage(&m);DispatchMessageA(&m);}WSACleanup();return 0;}
