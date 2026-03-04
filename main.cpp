#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <vector>
#include <string>
#include <set>

#pragma comment(lib, "ws2_32.lib")

#define ID_BUTTON 101
#define ID_LISTBOX 102

HWND hList;
std::set<std::string> dhcpServers;

#pragma pack(push, 1)
struct DHCPPacket {
    BYTE op;
    BYTE htype;
    BYTE hlen;
    BYTE hops;
    DWORD xid;
    WORD secs;
    WORD flags;
    DWORD ciaddr;
    DWORD yiaddr;
    DWORD siaddr;
    DWORD giaddr;
    BYTE chaddr[16];
    BYTE sname[64];
    BYTE file[128];
    DWORD magic_cookie;
    BYTE options[312];
};
#pragma pack(pop)

void DetectDHCP()
{
    dhcpServers.clear();
    SendMessage(hList, LB_RESETCONTENT, 0, 0);

    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    BOOL broadcast = TRUE;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char*)&broadcast, sizeof(broadcast));

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(68);
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(sock, (sockaddr*)&addr, sizeof(addr));

    sockaddr_in dest = {};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(67);
    dest.sin_addr.s_addr = INADDR_BROADCAST;

    DHCPPacket packet = {};
    packet.op = 1;
    packet.htype = 1;
    packet.hlen = 6;
    packet.xid = htonl(GetTickCount());
    packet.flags = htons(0x8000);
    packet.magic_cookie = htonl(0x63825363);

    packet.options[0] = 53;
    packet.options[1] = 1;
    packet.options[2] = 1;
    packet.options[3] = 255;

    sendto(sock, (char*)&packet, sizeof(packet), 0,
           (sockaddr*)&dest, sizeof(dest));

    fd_set readfds;
    timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;

    while (true)
    {
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);

        int result = select(0, &readfds, NULL, NULL, &tv);
        if (result <= 0)
            break;

        DHCPPacket recvPacket;
        sockaddr_in recvAddr;
        int len = sizeof(recvAddr);

        int recvLen = recvfrom(sock, (char*)&recvPacket,
                               sizeof(recvPacket), 0,
                               (sockaddr*)&recvAddr, &len);

        if (recvLen > 0)
        {
            BYTE* opt = recvPacket.options;
            for (int i = 0; i < 300; )
            {
                if (opt[i] == 255) break;

                if (opt[i] == 54 && opt[i+1] == 4)
                {
                    in_addr server;
                    memcpy(&server.s_addr, &opt[i+2], 4);
                    std::string ip = inet_ntoa(server);
                    dhcpServers.insert(ip);
                    break;
                }
                i += 2 + opt[i+1];
            }
        }
    }

    closesocket(sock);
    WSACleanup();

    for (auto& ip : dhcpServers)
    {
        SendMessageA(hList, LB_ADDSTRING, 0, (LPARAM)ip.c_str());
    }

    if (dhcpServers.size() > 1)
    {
        MessageBox(NULL,
            "警告：检测到多个 DHCP 服务器！\n可能会影响上网！",
            "DHCP 冲突",
            MB_ICONWARNING);
    }
    else if (dhcpServers.empty())
    {
        MessageBox(NULL,
            "未检测到 DHCP 服务器。",
            "结果",
            MB_ICONINFORMATION);
    }
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg,
                         WPARAM wParam, LPARAM lParam)
{
    switch(msg)
    {
        case WM_CREATE:
            CreateWindow("BUTTON", "检测 DHCP",
                WS_VISIBLE | WS_CHILD,
                20, 20, 120, 30,
                hwnd, (HMENU)ID_BUTTON,
                NULL, NULL);

            hList = CreateWindow("LISTBOX", "",
                WS_VISIBLE | WS_CHILD | WS_BORDER,
                20, 70, 300, 200,
                hwnd, (HMENU)ID_LISTBOX,
                NULL, NULL);
            break;

        case WM_COMMAND:
            if (LOWORD(wParam) == ID_BUTTON)
                DetectDHCP();
            break;

        case WM_DESTROY:
            PostQuitMessage(0);
            break;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance,
                   HINSTANCE,
                   LPSTR,
                   int nCmdShow)
{
    WNDCLASS wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "DHCPDetectClass";

    RegisterClass(&wc);

    HWND hwnd = CreateWindow(
        "DHCPDetectClass",
        "局域网 DHCP 检测工具",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        380, 350,
        NULL, NULL,
        hInstance, NULL);

    ShowWindow(hwnd, nCmdShow);

    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}
