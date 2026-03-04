#define WIN32_LEAN_AND_MEAN
#define _WINSOCKAPI_
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <thread>
#include <vector>
#include <set>
#include <string>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#define ID_BUTTON 101
#define ID_LISTBOX 102

HWND hList;
HWND hButton;

std::set<std::wstring> dhcpServers;

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

// 获取 MAC 地址
std::vector<BYTE> GetMacAddress()
{
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD buflen = sizeof(adapterInfo);
    GetAdaptersInfo(adapterInfo, &buflen);

    PIP_ADAPTER_INFO pAdapter = adapterInfo;
    while (pAdapter)
    {
        if (pAdapter->Type == MIB_IF_TYPE_ETHERNET)
        {
            return std::vector<BYTE>(
                pAdapter->Address,
                pAdapter->Address + pAdapter->AddressLength);
        }
        pAdapter = pAdapter->Next;
    }
    return {};
}

// 向 ListBox 添加宽字符串
void AddToList(const std::wstring& text)
{
    SendMessageW(hList, LB_ADDSTRING, 0, (LPARAM)text.c_str());
}

// DHCP 检测
void DetectDHCP()
{
    dhcpServers.clear();
    SendMessageW(hList, LB_RESETCONTENT, 0, 0);
    AddToList(L"正在检测 DHCP 服务器...");

    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    BOOL broadcast = TRUE;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST,
               (char*)&broadcast, sizeof(broadcast));

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(0); // 随机端口
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

    auto mac = GetMacAddress();
    if (mac.size() >= 6)
        memcpy(packet.chaddr, mac.data(), 6);

    BYTE* opt = packet.options;
    int idx = 0;

    // DHCP Discover
    opt[idx++] = 53;
    opt[idx++] = 1;
    opt[idx++] = 1;

    // Parameter Request List
    opt[idx++] = 55;
    opt[idx++] = 3;
    opt[idx++] = 1;
    opt[idx++] = 3;
    opt[idx++] = 6;

    opt[idx++] = 255;

    sendto(sock, (char*)&packet, sizeof(packet),
           0, (sockaddr*)&dest, sizeof(dest));

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

        int recvLen = recvfrom(sock,
            (char*)&recvPacket,
            sizeof(recvPacket),
            0,
            (sockaddr*)&recvAddr,
            &len);

        if (recvLen > 0)
        {
            BYTE* ropt = recvPacket.options;
            for (int i = 0; i < 300;)
            {
                if (ropt[i] == 255)
                    break;

                if (ropt[i] == 54 && ropt[i+1] == 4)
                {
                    in_addr server;
                    memcpy(&server.s_addr,
                           &ropt[i+2], 4);

                    wchar_t ipStr[32];
                    InetNtopW(AF_INET,
                              &server,
                              ipStr,
                              32);

                    dhcpServers.insert(ipStr);
                    break;
                }

                i += 2 + ropt[i+1];
            }
        }
    }

    closesocket(sock);
    WSACleanup();

    SendMessageW(hList, LB_RESETCONTENT, 0, 0);

    if (dhcpServers.empty())
    {
        AddToList(L"未检测到 DHCP 服务器。");
    }
    else
    {
        for (auto& ip : dhcpServers)
            AddToList(ip);

        if (dhcpServers.size() > 1)
        {
            MessageBoxW(NULL,
                L"警告：检测到多个 DHCP 服务器！\n可能会影响网络稳定！",
                L"DHCP 冲突警告",
                MB_ICONWARNING);
        }
    }

    EnableWindow(hButton, TRUE);
}

// 启动检测线程
void StartDetectThread()
{
    EnableWindow(hButton, FALSE);
    std::thread([]() {
        DetectDHCP();
    }).detach();
}

// 窗口回调
LRESULT CALLBACK WndProc(HWND hwnd,
                         UINT msg,
                         WPARAM wParam,
                         LPARAM lParam)
{
    switch(msg)
    {
        case WM_CREATE:
            hButton = CreateWindowW(
                L"BUTTON",
                L"检测 DHCP",
                WS_VISIBLE | WS_CHILD,
                20, 20, 120, 30,
                hwnd,
                (HMENU)ID_BUTTON,
                NULL, NULL);

            hList = CreateWindowW(
                L"LISTBOX",
                L"",
                WS_VISIBLE | WS_CHILD | WS_BORDER,
                20, 70, 320, 200,
                hwnd,
                (HMENU)ID_LISTBOX,
                NULL, NULL);
            break;

        case WM_COMMAND:
            if (LOWORD(wParam) == ID_BUTTON)
                StartDetectThread();
            break;

        case WM_DESTROY:
            PostQuitMessage(0);
            break;
    }

    return DefWindowProc(hwnd, msg,
                         wParam, lParam);
}

// 主函数
int WINAPI wWinMain(HINSTANCE hInstance,
                    HINSTANCE,
                    PWSTR,
                    int nCmdShow)
{
    WNDCLASSW wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"DHCPDetectClass";

    RegisterClassW(&wc);

    HWND hwnd = CreateWindowW(
        L"DHCPDetectClass",
        L"局域网 DHCP 冲突检测工具",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        400, 340,
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
